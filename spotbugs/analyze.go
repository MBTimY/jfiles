package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/instance"
	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/project"
	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/sdkman"
	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/utils"
)

const (
	flagCompile   = "compile"
	flagFailNever = "fail-never"
	flagJavaOpts  = "javaOpts"
	pathExclude   = "/spotbugs/exclude.xml"
	pathInclude   = "/spotbugs/include.xml"
	pathJarsList  = "/tmp/jars.list"
	pathOutput    = "/tmp/SpotBugs.xml"
	pathSpotBugs  = "/spotbugs/dist"
	pluginList    = "/fsb/lib/findsecbugs-plugin.jar"
)

func analyzeFlags() []cli.Flag {
	home, ok := os.LookupEnv("HOME")
	if !ok {
		home = "/"
	}
	return []cli.Flag{
		cli.StringFlag{
			Name:   project.FlagAntPath,
			Usage:  "Define path to ant executable.",
			Value:  "ant",
			EnvVar: "ANT_PATH",
		},
		cli.StringFlag{
			Name:   project.FlagAntHome,
			Usage:  "Define ANT_HOME.",
			Value:  "",
			EnvVar: "ANT_HOME",
		},
		cli.BoolTFlag{
			Name:   flagCompile,
			Usage:  "Compile source code. It's not needed if the code is already compiled.",
			EnvVar: "COMPILE",
		},
		cli.BoolFlag{
			Name:   flagFailNever,
			Usage:  "Ignore compilation failures, attempt scan anyway.",
			EnvVar: "FAIL_NEVER",
		},
		cli.StringFlag{
			Name:   flagJavaOpts,
			Usage:  "Define JAVA_OPTS.",
			Value:  "-Xmx1900M",
			EnvVar: "JAVA_OPTS",
		},
		cli.StringFlag{
			Name:   project.FlagGradlePath,
			Usage:  "Define path to gradle executable.",
			Value:  "gradle",
			EnvVar: "GRADLE_PATH",
		},
		cli.StringFlag{
			Name:   project.FlagMavenCliOpts,
			Value:  "--batch-mode -DskipTests=true",
			Usage:  "Optional arguments for the maven CLI (use batch mode and skip tests by default)",
			EnvVar: "MAVEN_CLI_OPTS",
		},
		cli.StringFlag{
			Name:   project.FlagMavenPath,
			Usage:  "Define path to mvn executable.",
			Value:  "mvn",
			EnvVar: "MAVEN_PATH",
		},
		cli.StringFlag{
			Name:   project.FlagMavenRepoPath,
			Usage:  "Define path to Maven local repository.",
			Value:  filepath.Join(home, ".m2", "repository"),
			EnvVar: "MAVEN_REPO_PATH",
		},
		cli.StringFlag{
			Name:   project.FlagSBTPath,
			Usage:  "Define path to sbt executable.",
			Value:  "sbt",
			EnvVar: "SBT_PATH",
		},
		cli.StringFlag{
			Name:   sdkman.FlagJavaPath,
			Usage:  "Define path to java executable.",
			Value:  "java",
			EnvVar: "JAVA_PATH",
		},
		cli.StringFlag{
			Name:   sdkman.FlagJavaVersion,
			Usage:  "Define which major Java version to use.",
			Value:  "8",
			EnvVar: "SAST_JAVA_VERSION",
		},
		cli.StringFlag{
			Name:   sdkman.FlagJava8Version,
			Usage:  "Define which version of Java 8 to use.",
			Value:  "8.0.242.hs-adpt",
			EnvVar: "JAVA_8_VERSION",
		},
		cli.StringFlag{
			Name:   sdkman.FlagJava11Version,
			Usage:  "Define which version of Java 11 to use.",
			Value:  "11.0.6.hs-adpt",
			EnvVar: "JAVA_11_VERSION",
		},
		cli.StringFlag{
			Name:   sdkman.FlagSdkmanDir,
			Usage:  "Define path to sdkman home directory.",
			Value:  "/usr/local/sdkman",
			EnvVar: "SDKMAN_DIR",
		},
	}
}

// Set compile function as package-level var to make mocking easier
var compileProj = compile

// analyze compiles (if asked) and analyzes every buildable project found in the given directory
func analyze(c *cli.Context, repositoryPath string) (io.ReadCloser, error) {
	sdkman.SetupSystemJava(c)

	projects, err := project.FindProjects(repositoryPath, false)
	if err != nil {
		return nil, err
	}

	log.Infof("Found %d analyzable projects.\n", len(projects))

	// Compile source code if needed.
	if c.BoolT(flagCompile) {
		if err := compileProj(c, projects, c.Bool(flagFailNever)); err != nil {
			return nil, err
		}
	}

	// Create a new Instances struct, it will receive the content of each fsb XML report.
	finalReport := instance.Instances{}

	// Run SpotBugs on projects.
	for _, p := range projects {
		bugInstances, err := analyzeProject(c, p)
		if err != nil {
			// Fail if even one report fails to be processed, to avoid false negatives.
			return nil, err
		}

		corrected, err := correctPath(repositoryPath, p, bugInstances)
		if err != nil {
			// Fail if even one report fails to be processed, to avoid false negatives.
			return nil, err
		}

		finalReport.Instances = append(finalReport.Instances, corrected...)
	}

	// Sort reports by filename for repeatable comparison in tests.
	instance.By(fileName).Sort(finalReport.Instances)

	return marshallToXML(c, finalReport)

}

// analyzeProject runs SpotBugs of a project directory
func analyzeProject(c *cli.Context, p project.Project) ([]instance.Instance, error) {
	// Build a file containing the list of JARs libraries used by the project
	if err := buildJarsList(c, p); err != nil {
		return nil, err
	}

	params, err := buildSpotBugsParams(c, p)
	// log.Infof(strings.Join(params, " "))
	if err != nil {
		log.Errorf("Error: Couldn't build the spotbugs command parameter list: %v\n", err)
		return nil, err
	}

	// Run the SpotBugs command line tool on the project
	cmd := utils.SetupCmdNoStd(
		p.Path,
		exec.Command(
			sdkman.JavaPath(c),
			params...))

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorf(
			"Error: SpotBugs analysis failed for %s: %s\n",
			p.Path,
			err.Error())
		return nil, err
	}
	log.Debugf("%s\n%s", cmd.String(), output)

	if strings.Contains(string(output), "No classfiles specified; output will have no warnings") {
		// No classes were found, this could mean the build process failed.
		log.Warnf("SpotBugs didn't find any class file to analyze in %s !\n", p.Path)
	} else {
		log.Infof("SpotBugs analysis succeeded for %s!\n", p.Path)
	}

	// read the XML report into a struct
	reportFile, err := os.Open(pathOutput)
	if err != nil {
		log.Errorf("Error: Unable to open XML report %s: %s\n", pathOutput, err.Error())
		return nil, err
	}
	defer utils.WithWarning(fmt.Sprintf("Couldn't close %s", pathOutput), reportFile.Close)

	bugInstances := &instance.Instances{}
	err = xml.NewDecoder(reportFile).Decode(&bugInstances)
	if err != nil {
		log.Errorf("Error: Unable to parse XML report %s: %s\n", pathOutput, err.Error())
		return nil, err
	}

	return bugInstances.Instances, nil
}

// buildSpotBugsParams build the arguments for the SpotBugs command
func buildSpotBugsParams(c *cli.Context, p project.Project) ([]string, error) {
	// build the list of packages to analyze
	packages := p.Packages()
	packageList := make([]string, len(packages))
	for i, p := range packages {
		packageList[i] = p + ".*"
	}

	// Gather target directories. They contain the generated .class files.
	targets, err := getTargetDirs(p)
	if err != nil {
		log.Errorf("Error: Couldn't get a list of target directories in %s: %v\n", p.Path, err)
		return nil, err
	}

	args := []string{
		"-cp", pathSpotBugs + "/lib/*",
		c.String(flagJavaOpts),
		"-jar", pathSpotBugs + "/lib/spotbugs.jar",
		"-pluginList", pluginList,
		"-exclude", pathExclude,
		"-include", pathInclude,
		"-onlyAnalyze", strings.Join(packageList, ","), // Don't analyze packages not in the source files.
		"-quiet",
		"-effort:max", // Max precision and more vulnerabilities found.
		"-low",        // Report all bugs.
		"-noClassOk",  // Don't fail on absence of .class files (we handle this case).
		"-xml:withMessages",
		"-auxclasspathFromFile", pathJarsList,
		"-output", pathOutput,
	}
	args = append(args, p.Path)
	return append(args, targets...), nil

}

// buildJarsList writes a list of .jar files used by the project into a file.
func buildJarsList(c *cli.Context, p project.Project) error {
	f, err := os.OpenFile(pathJarsList, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer utils.WithWarning(fmt.Sprintf("Warning: Couldn't close jar list file %s", pathJarsList), f.Close)

	if p.UsesMaven() {
		// Add .jar files from the local Maven repository for Maven projects.
		localRepo := c.String(project.FlagMavenRepoPath)
		if []rune(localRepo)[0] != '/' {
			// This path is relative to the project path, get a full path.
			localRepo = filepath.Join(p.Path, localRepo)
		}

		return filepath.Walk(localRepo, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && filepath.Ext(info.Name()) == ".jar" {
				if _, err := fmt.Fprintln(f, path); err != nil {
					return err
				}
			}
			return nil
		})
	}

	return nil
}

func compile(c *cli.Context, projects []project.Project, failNever bool) error {

	// Use the builder defined in the projects to compile them
	for _, p := range projects {
		if err := p.Build(c); err != nil {
			if !failNever {
				return err
			}

			// None of the builders succeeded
			log.Warnf("Warning: Building failed for %s. Attempting scan anyway.\n", p.Path)
		}
	}

	return nil
}

// correctPath corrects the SourceLine.SourcePath field so that it is relative to the repository root
// so that users can immediately find the file without needing to search for it themselves.
func correctPath(repositoryPath string, p project.Project, bugInstances []instance.Instance) ([]instance.Instance, error) {
	var result []instance.Instance
	for _, bugInstance := range bugInstances {
		// Reported path only contains directory names corresponding to java packages
		// We need to get the path relative to the project path first.
		reportedPath := bugInstance.SourceLine.SourcePath
		projectRelativePath, err := p.RelativePath(reportedPath)
		if err != nil {
			// This source file isn't in the project. It's certainly present in a jar file and shouldn't
			// be reported.
			continue
		}

		// Now get the path relative to the repository path.
		fullPath := filepath.Join(p.Path, projectRelativePath)
		repositoryRelativePath, err := filepath.Rel(repositoryPath, fullPath)
		if err != nil {
			return nil, err
		}

		bugInstance.SourceLine.SourcePath = repositoryRelativePath

		// Append bug instances to the result.
		result = append(result, bugInstance)
	}

	return result, nil
}

// fileName sorts reports by filename for repeatable comparison in tests.
func fileName(b1, b2 *instance.Instance) bool {
	// Compare by file name first.
	p1, p2 := b1.SourceLine.SourcePath, b2.SourceLine.SourcePath

	if p1 < p2 {
		return true
	}

	if p2 < p1 {
		return false
	}

	// Next compare start lines.
	s1, s2 := b1.SourceLine.Start, b2.SourceLine.Start

	if s1 < s2 {
		return true
	}

	if s2 < s1 {
		return false
	}

	// Then by short message.
	return b1.ShortMessage < b2.ShortMessage
}

// getTargetDirs returns the list of directories named "target" in the project directory
func getTargetDirs(p project.Project) ([]string, error) {
	var targets []string
	err := filepath.Walk(p.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() == "target" {
			targets = append(targets, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return targets, nil
}

func marshallToXML(c *cli.Context, instances instance.Instances) (io.ReadCloser, error) {
	// Marshall the final report to XML
	xml, err := xml.Marshal(instances)
	if err != nil {
		log.Errorf("Error: Unable to encode final XML report: %s\n", err.Error())
		return nil, err
	}

	return ioutil.NopCloser(bytes.NewReader(xml)), nil
}
