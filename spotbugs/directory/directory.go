// Package directory provides a representation of a directory tree with, in particular,
// a method used to match partial file paths to actual ones.
package directory

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Directory represents a file system Directory, with its children directories and files
type Directory struct {
	Name        string
	Parent      *Directory
	files       map[string]bool
	directories []*Directory
}

// NewDirectory returns a new Directory
func NewDirectory(name string, parent *Directory) *Directory {
	return &Directory{
		Name:   name,
		Parent: parent,
		files:  make(map[string]bool)}
}

// PrintFiles prints file names in the directory tree to stdout.
func (d *Directory) PrintFiles() {
	d.printFiles("")
}

func (d *Directory) printFiles(path string) {
	fileNames := make([]string, len(d.files))
	i := 0
	for k := range d.files {
		fileNames[i] = k
		i++
	}

	for _, f := range fileNames {
		log.Infof("%s/%s\n", path, f)
	}
	for _, childDir := range d.directories {
		childDir.printFiles(filepath.Join(path, childDir.Name))
	}
}

func (d *Directory) addOrCreateFile(name string) {
	d.files[name] = true
}

// addOrCreateDirectory adds or create a directory is it's missing
// from the struct, and returns the directory.
func (d *Directory) addOrCreateDirectory(name string) *Directory {
	for _, subDirectory := range d.directories {
		if subDirectory.Name == name {
			// The Directory already exists, return it
			return subDirectory
		}
	}

	// The Directory doesn't exist yet, create it and return it
	newDirectory := NewDirectory(name, d)
	d.directories = append(d.directories, newDirectory)

	return newDirectory
}

// AddSourceFileComponents adds component of the file path to a tree
func (d *Directory) AddSourceFileComponents(components []string) {
	head := components[0]
	tail := components[1:]

	if len(tail) == 0 {
		// We reached the source file. Add it
		d.addOrCreateFile(head)
	} else {
		// This is a Directory, add it and recurse
		d.addOrCreateDirectory(head).AddSourceFileComponents(tail)
	}
}

// GetMatchingPath returns the Directory and fileName corresponding to
// the partial path, as found in the directory tree.
func (d *Directory) GetMatchingPath(path string) (*Directory, string, error) {
	// Split path into its components
	components := strings.Split(path, string(os.PathSeparator))
	// Also prepare components with the file name removed
	directoryComponents := components[0 : len(components)-1]

	// Search the tree for directories containing the file
	fileName := components[len(components)-1]
	results := d.getDirectoriesContainingFile(fileName)

	// Check each, verifying that the components match
	results2 := make([]*Directory, 0)
	for _, directory := range results {
		if directory.parentsMatch(directoryComponents) {
			// Directory's parent match our path, add it
			results2 = append(results2, directory)
		}
	}

	if len(results2) == 0 {
		// The file was not found. This shouldn't happen.
		return nil, "", fmt.Errorf("couldn't find the relative path of file %s", path)
	}

	// We now have a list of directories whose path matches the path.
	// Return the first one as there will probably never be more than one and
	// we don't have any more criteria to use to choose the "best" one.
	return results2[0], fileName, nil
}

// PathRelativeTo returns a string representation of the Directory's path relative
// to a root directory.
func (d *Directory) PathRelativeTo(root *Directory) string {
	if d.Parent == root {
		// We reached the root, don't go further
		return d.Name
	}

	// Recurse
	return filepath.Join(d.Parent.PathRelativeTo(root), d.Name)
}

// getDirectoriesContainingFile return a list of directories containing the given file name
func (d *Directory) getDirectoriesContainingFile(fileName string) []*Directory {
	results := make([]*Directory, 0)

	if _, ok := d.files[fileName]; ok {
		// The file is present in this Directory, add it
		results = append(results, d)
	}

	// Recurse
	for _, directory := range d.directories {
		results = append(results, directory.getDirectoriesContainingFile(fileName)...)
	}

	return results
}

// HasMatchingDescendantFile return true if a file whose name
// matches the regular expression is present in the directory tree
func (d *Directory) HasMatchingDescendantFile(fileRegexp *regexp.Regexp) bool {
	for name := range d.files {
		if fileRegexp.MatchString(name) {
			return true
		}
	}

	// Recurse
	for _, directory := range d.directories {
		if directory.HasMatchingDescendantFile(fileRegexp) {
			return true
		}
	}

	return false
}

// parentsMatch examines a directory ancestors, returning true only if they
// all are equal to the provided list.
func (d *Directory) parentsMatch(components []string) bool {
	if len(components) == 0 {
		// No parent directory is present.
		return true
	}

	directoryName := components[len(components)-1]
	parents := components[:len(components)-1]

	if directoryName != d.Name {
		// Directory name of this parent doesn't match
		return false
	}

	if len(parents) == 0 {
		// No more parent to check
		return true
	}

	// Recurse
	return d.Parent.parentsMatch(parents)
}
