package project

import (
	"io"
	"math"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/termie/go-shutil"
	"github.com/urfave/cli"

	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/utils"
)

const (
	pathExtraBuildGradle = "/spotbugs/build.gradle"

	// FlagAntPath is the name of spotbug's cli ant path argument
	FlagAntPath = "antPath"
	// FlagAntHome is the name of spotbug's cli ant home argument
	FlagAntHome = "antHome"
	// FlagGradlePath is the name of spotbug's cli gradle path argument
	FlagGradlePath = "gradlePath"
	// FlagMavenPath is the name of spotbug's cli maven path argument
	FlagMavenPath = "mavenPath"
	// FlagMavenRepoPath is the name of spotbug's cli maven repo path argument
	FlagMavenRepoPath = "mavenLocalRepository"
	// FlagMavenCliOpts is the name of spotbug's cli maven cli options argument
	FlagMavenCliOpts = "mavenCliOpts"
	// FlagSBTPath is the name of spotbug's cli SBT path argument
	FlagSBTPath = "sbtPath"
)

type builder struct {
	name      string
	filename  string
	buildFunc func(builder *builder, context *cli.Context, p *Project) error // builds the project
}

type procedure func() error

// build exists only to pass a reference to the builder struct to its buildFunc function field
func (builder *builder) build(context *cli.Context, p *Project) error {
	return builder.buildFunc(builder, context, p)
}

func (builder *builder) canBuild(info os.FileInfo) bool {
	return info.Name() == builder.filename
}

// withGradleStaticCompilation returns a function that runs the given procedure after configuring a Gradle project
// to be statically compiled. It then restores the original configuration.
func withGradleStaticCompilation(p *Project, build procedure) procedure {
	buildFile := filepath.Join(p.Path, "build.gradle")

	return withFileRestoration(buildFile, func() error {
		// Append extra configuration to build.gradle
		from, err := os.Open(pathExtraBuildGradle)
		if err != nil {
			return err
		}

		to, err := os.OpenFile(buildFile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}

		if _, err := io.Copy(to, from); err != nil {
			return err
		}

		// Close files
		err = from.Close()
		if err != nil {
			return err
		}

		err = to.Close()
		if err != nil {
			return err
		}

		// Execute build function
		return build()
	})
}

// withFileRestoration return a function that runs the given procedure after making a backup of the given file.
// It then restores the file content.
func withFileRestoration(filePath string, build procedure) procedure {
	return func() error {
		backup := filePath + ".bak"

		// Backup original file
		_, err := shutil.Copy(filePath, backup, false)
		if err != nil {
			return err
		}

		// Execute build function
		err = build()

		// Restore file once done
		_, err2 := shutil.Copy(backup, filePath, false)
		if err2 != nil {
			return err2
		}

		return err
	}
}

// withCleanup returns a function that runs the given procedure and then removes created files if the procedure failed
func withCleanup(argPath string, build procedure) procedure {
	return func() error {
		// Record files names before build
		f, err := os.Open(argPath)
		if err != nil {
			return err
		}

		files, err := f.Readdirnames(-1)
		if err != nil {
			return err
		}

		if err = f.Close(); err != nil {
			return err
		}

		oldFiles := make(map[string]bool, len(files))

		for _, f := range files {
			oldFiles[f] = true
		}

		// Execute build function
		err = build()

		if err != nil {
			// Remove new files
			f, err2 := os.Open(argPath)
			if err2 != nil {
				return err2
			}

			newFiles, err2 := f.Readdirnames(-1)
			if err2 != nil {
				return err2
			}

			if err2 = f.Close(); err2 != nil {
				return err2
			}

			for _, f := range newFiles {
				if !oldFiles[f] {
					// This file has been added by the run, remove it
					_ = os.RemoveAll(filepath.Join(argPath, f))
				}
			}
		}

		return err
	}
}

// buildGradle tries building a gradle project with static compilation, and if it fails non-static compilation.
func buildGradle(builder *builder, c *cli.Context, p *Project, build procedure) error {
	if p.isGroovy() {
		// For Groovy projects, first try a static compilation as it allows FindSecBugs to find more vulnerabilites
		log.Infof("Building %s project at %s with static compilation.\n", builder.name, p.Path)

		err := withCleanup(p.Path, withGradleStaticCompilation(p, build))()
		if err == nil {
			// Success, don't try a non static build
			log.Info("Project built.")
			return nil
		}

		// It didn't work, so try a non static build
		log.Infof("Building failed, trying building without static compilation: %s\n", err.Error())
	}

	log.Infof("Building %s project at %s.\n", builder.name, p.Path)
	if err := withCleanup(p.Path, build)(); err != nil {
		log.Errorf("Project couldn't be built: %s\n", err.Error())
		return err
	}

	log.Info("Project built.")
	return nil
}

// buildGeneric tries building a project with the given procedure
func buildGeneric(builder *builder, c *cli.Context, p *Project, build procedure) error {
	log.Infof("Building %s project at %s.\n", builder.name, p.Path)
	if err := withCleanup(p.Path, build)(); err != nil {
		log.Errorf("Project couldn't be built: %s\n", err.Error())
		return err
	}

	log.Info("Project built.")
	return nil
}

// deleteEmpty returns a copy of the slice without empty strings.
func deleteEmpty(strs []string) []string {
	r := make([]string, 0, len(strs))
	for _, str := range strs {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}

var builders = []builder{
	// The SBT builder will use SBT to compile the project.
	{
		name:     "SBT",
		filename: "build.sbt",
		buildFunc: func(builder *builder, c *cli.Context, p *Project) error {
			return buildGradle(builder, c, p, func() error {
				cmd := utils.SetupCmdNoStd(p.Path, exec.Command(c.String(FlagSBTPath), "compile"))
				return utils.RunCmd(cmd)
			})
		},
	},
	// The Grailsw builder will try to run the grailsw wrapper script to compile the project.
	{
		name:     "Grailsw",
		filename: "grailsw",
		buildFunc: func(builder *builder, c *cli.Context, p *Project) error {
			return buildGradle(builder, c, p, func() error {
				cmd := utils.SetupCmdNoStd(p.Path, exec.Command(path.Join(p.Path, "grailsw"), "compile"))
				return utils.RunCmdWithTextErrorDetection(
					cmd,
					c,
					"BUILD FAILED",
					"grails failed to compile the project")
			})
		},
	},
	// The Gradlew builder will try to run the gradlew wrapper script to build the project.
	{
		name:     "Gradlew",
		filename: "gradlew",
		buildFunc: func(builder *builder, c *cli.Context, p *Project) error {
			return buildGradle(builder, c, p, func() error {
				cmd := utils.SetupCmdNoStd(p.Path, exec.Command(path.Join(p.Path, "gradlew"), "build"))
				return utils.RunCmd(cmd)
			})
		},
	},
	// The Gradle builder will try to use Gradle to build the project.
	{
		name:     "Gradle",
		filename: "build.gradle",
		buildFunc: func(builder *builder, c *cli.Context, p *Project) error {
			return buildGradle(builder, c, p, func() error {
				cmd := utils.SetupCmdNoStd(p.Path, exec.Command(c.String(FlagGradlePath), "build"))
				return utils.RunCmd(cmd)
			})
		},
	},
	// The Mvnw builder will try to run the mvnw wrapper script to compile the project
	// It is lower on the list since setting up static compilation of Groovy files isn't
	// implemented for it.
	{
		name:     "Mvnw",
		filename: "mvnw",
		buildFunc: func(builder *builder, c *cli.Context, p *Project) error {
			return buildGeneric(builder, c, p, func() error {
				args := []string{"-Dmaven.repo.local=" + c.String(FlagMavenRepoPath)}
				args = append(args, strings.Split(c.String(FlagMavenCliOpts), " ")...)
				args = deleteEmpty(append(args, "install"))
				cmd := utils.SetupCmdNoStd(p.Path, exec.Command(
					path.Join(p.Path, "mvnw"),
					args...))
				return utils.RunCmd(cmd)
			})
		},
	},
	// The Maven builder will try to use Maven to compile the project
	// It is lower on the list since setting up static compilation of Groovy files isn't
	// implemented for it.
	{
		name:     "Maven",
		filename: "pom.xml",
		buildFunc: func(builder *builder, c *cli.Context, p *Project) error {
			return buildGeneric(builder, c, p, func() error {
				args := []string{"-Dmaven.repo.local=" + c.String(FlagMavenRepoPath)}
				args = append(args, strings.Split(c.String(FlagMavenCliOpts), " ")...)
				args = deleteEmpty(append(args, "install"))
				cmd := utils.SetupCmdNoStd(p.Path, exec.Command(
					c.String(FlagMavenPath),
					args...))
				return utils.RunCmd(cmd)
			})
		},
	},
	// The Ant builder will try to use Ant to compile the project
	// It is lower on the list since setting up static compilation of Groovy files isn't
	// implemented for it.
	{
		name:     "Ant",
		filename: "build.xml",
		buildFunc: func(builder *builder, c *cli.Context, p *Project) error {
			return buildGeneric(builder, c, p, func() error {
				if antHome := c.String(FlagAntHome); antHome != "" {
					// Set the ANT_HOME environment according to the command line flag
					previous, wasDefined := os.LookupEnv("ANT_HOME")
					os.Setenv("ANT_HOME", antHome)
					if wasDefined {
						// Restore ANT_HOME on return
						defer os.Setenv("ANT_HOME", previous)
					} else {
						// Remove ANT_HOME on return
						defer os.Unsetenv("ANT_HOME")
					}
				}
				cmd := utils.SetupCmdNoStd(p.Path, exec.Command(c.String(FlagAntPath)))
				return utils.RunCmd(cmd)
			})
		},
	},
}

// HasBuilder returns true if the file passed to it is recognised by any of the builders
func HasBuilder(info os.FileInfo) bool {
	for _, b := range builders {
		if b.canBuild(info) {
			return true
		}
	}

	return false
}

// bestBuilder returns the best builder for a set of files
func bestBuilder(infos []os.FileInfo) *builder {
	bestBuilder := math.MaxInt32

	// Run each Builders' detection on every files
	for _, f := range infos {
		for i, b := range builders {
			if b.canBuild(f) && i < bestBuilder {
				// Remember the best builder we found
				bestBuilder = i
			}
		}
	}

	if bestBuilder != math.MaxInt32 {
		// builder found
		return &builders[bestBuilder]
	}

	return nil
}
