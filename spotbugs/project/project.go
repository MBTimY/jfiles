// Package project provides the Project type, representing a file directory containing a buildable Java project.
// A method is provided to find all projects in a directory.
//
// The Project type offers 3 things:
// - a method to build the project
// - a method to obtain complete file paths relative to the project root when given partial file paths as appear in
//   SpotBugs reports
// - the list of packages, as read from each source file during newProject execution.
package project

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/directory"
)

// Project represents a buildable project.
type Project struct {
	Path            string
	SourceFilesTree *directory.Directory
	builder         *builder
	packages        map[string]bool
}

type errNoCompatibleBuilder struct {
	path string
}

func (e errNoCompatibleBuilder) Error() string {
	return "Cannot find compatible builder for project path: " + e.path
}

type filesFirstWalkFunc func(directory string, infos []os.FileInfo) error

var packageMatcher = regexp.MustCompile("package\\s+([a-z][a-z0-9_\\.]*)")
var sourceFileMatcher = regexp.MustCompile("(\\.groovy|\\.java|\\.scala)$")
var groovyFileMatcher = regexp.MustCompile("\\.groovy$")

// FindProjects walks the directory tree and returns a list of detected Project that can be built and analyzed
// It doesn't use filepath.Walk because it walks files one at a time which is unsuitable in our case ; we need
// the full list of files in a directory to determine which builder is best suited for it.
func FindProjects(path string, quiet bool) ([]Project, error) {
	projects := make([]Project, 0)

	err := filesFirstWalk(path, func(directory string, infos []os.FileInfo) error {
		// Test buildability of each file.
		foundBuilder := false
		for _, f := range infos {
			if HasBuilder(f) {
				foundBuilder = true
			}
		}

		if !foundBuilder {
			// Nothing found, go on.
			return nil
		}

		// Create a project for this directory.
		project, err := newProject(directory)
		if err != nil {
			return err
		}

		if !quiet {
			log.Infof("Found %s project in %s directory\n", project.builder.name, directory)
		}

		projects = append(projects, *project)

		// Keep searching the descendant for possible sub-projects.
		return nil
	})
	if err != nil {
		return nil, err
	}

	return projects, nil
}

// filesFirstWalk walks a tree, and gives a list of all the file info to the provided function so that
// the function can make decisions it couldn't with a classic filepath.Walk.
func filesFirstWalk(root string, walkFn filesFirstWalkFunc) error {
	err := filesFirstWalkRec(root, walkFn)
	if err == filepath.SkipDir {
		return nil
	}

	return err
}

func filesFirstWalkRec(path string, walkFn filesFirstWalkFunc) error {
	// Run walkFn with the list of non directory entries first.
	f, err := os.Open(path)
	if err != nil {
		return err
	}

	names, err := f.Readdirnames(-1)
	if err != nil {
		return err
	}

	if err = f.Close(); err != nil {
		return err
	}

	// Get file infos and filter out directories.
	infos := make([]os.FileInfo, 0)
	for _, name := range names {
		filename := filepath.Join(path, name)

		fileInfo, err := os.Lstat(filename)
		if err != nil {
			return err
		}

		if !fileInfo.IsDir() {
			infos = append(infos, fileInfo)
		}
	}

	err = walkFn(path, infos)
	if err != nil {
		// walkFn wants to skip this directory.
		return nil
	}

	// Walk all directories now.
	f, err = os.Open(path)
	if err != nil {
		return err
	}

	names, err = f.Readdirnames(-1)
	if err != nil {
		return err
	}

	if err = f.Close(); err != nil {
		return err
	}

	// Get file infos and keep only directories.
	infos = make([]os.FileInfo, 0)
	for _, name := range names {
		filename := filepath.Join(path, name)

		fileInfo, err := os.Lstat(filename)
		if err != nil {
			return err
		}

		if fileInfo.IsDir() {
			infos = append(infos, fileInfo)
		}
	}

	for _, info := range infos {
		filename := filepath.Join(path, info.Name())

		err = filesFirstWalkRec(filename, walkFn)
		if err != nil {
			return nil
		}
	}
	return nil
}

func newProject(path string) (*Project, error) {
	p := new(Project)
	p.Path = path
	p.SourceFilesTree = directory.NewDirectory("", nil)
	p.packages = make(map[string]bool)

	err := p.recordSourceFiles()
	if err != nil {
		return nil, err
	}

	if p.builder == nil {
		return nil, errNoCompatibleBuilder{path}
	}

	return p, nil
}

// UsesMaven convenience function, returns true if the project uses Maven or its variants.
func (p *Project) UsesMaven() bool {
	switch p.builder.name {
	case "Maven", "Mvnw":
		return true
	default:
		return false
	}
}

// Packages return a list of packages present in the project source code files, without duplicates.
func (p *Project) Packages() []string {
	keys := make([]string, len(p.packages))
	i := 0

	for k := range p.packages {
		keys[i] = k
		i++
	}

	return keys
}

// isGroovy returns true if Groovy source files are present in the project.
func (p *Project) isGroovy() bool {
	return p.SourceFilesTree.HasMatchingDescendantFile(groovyFileMatcher)
}

// addSourceFile add the path to the SourceFilesTree of the project, relative to the project path
// also extract the package name from the file to add it to the project.
func (p *Project) addSourceFile(path string) error {
	relPath, err := filepath.Rel(p.Path, path)
	if err != nil {
		return err
	}

	// Add to project files
	components := strings.Split(relPath, string(os.PathSeparator))
	p.SourceFilesTree.AddSourceFileComponents(components)

	// Add package name
	return p.addPackageFromSourceFile(path)
}

// addPackageFromSourceFile reads a java or groovy file and add the detected package name to the
// project.
func (p *Project) addPackageFromSourceFile(path string) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	match := packageMatcher.FindSubmatch(content)
	if len(match) > 1 {
		p.packages[string(match[1])] = true
	}

	return nil
}

// Build builds the project.
func (p *Project) Build(c *cli.Context) error {
	return p.builder.build(c, p)
}

// recordSourceFiles explores the project tree, to add every Java and Groovy source files
// to the SourceFile field, relative to the project root.
// This is used after running the tool to filter results.
// It also detects which builders can build the project.
func (p *Project) recordSourceFiles() error {
	return filesFirstWalk(p.Path, p.recordSourceFilesWalk)
}

func (p *Project) recordSourceFilesWalk(directory string, infos []os.FileInfo) error {
	// Ignore Gradle config files
	if filepath.Base(directory) == "gradle" {
		return filepath.SkipDir
	}

	if p.builder == nil {
		// Set best builder for these files in the project (or nil if none if detected).
		p.builder = bestBuilder(infos)
	}

	// Add source files.
	for _, info := range infos {
		if sourceFileMatcher.MatchString(info.Name()) {
			// Add recognized source code files to the project
			if err := p.addSourceFile(filepath.Join(directory, info.Name())); err != nil {
				return err
			}
		}
	}

	return nil
}

// RelativePath takes a path reported by FindSecBug and returns the
// path relative to the project root.
// Exemple:
//   path: org/gizmotech/awesometool/Wow.java
//
//   result: awesometool/mysubfolder/src/main/java/org/gizmotech/awesometool/Wow.java
func (p *Project) RelativePath(path string) (string, error) {
	// Get the directory containing the source file
	f, fileName, err := p.SourceFilesTree.GetMatchingPath(path)
	if err != nil {
		return "", err
	}

	return filepath.Join(f.PathRelativeTo(p.SourceFilesTree), fileName), nil
}
