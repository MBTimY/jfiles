package directory

import (
	"testing"
)

func TestDirectory_addOrCreateFile(t *testing.T) {
	root := NewDirectory("root", nil)

	// Test file addition
	root.addOrCreateFile("file.txt")
	value, ok := root.files["file.txt"]
	if len(root.files) != 1 || !value || !ok {
		// Something went wrong
		t.Error("addOrCreateFile(): Couldn't add file.txt correctly")
	}

	// Test another file addition
	root.addOrCreateFile("file2.txt")
	value, ok = root.files["file2.txt"]
	if len(root.files) != 2 || !value || !ok {
		// Something went wrong
		t.Error("addOrCreateFile(): Couldn't add file2.txt correctly")
	}

	// Test adding the same file again
	root.addOrCreateFile("file2.txt")
	value, ok = root.files["file2.txt"]
	if len(root.files) != 2 || !value || !ok {
		// Something went wrong
		t.Error("addOrCreateFile(): Couldn't add file2.txt again correctly")
	}
}

func TestDirectory_addOrCreateDirectory(t *testing.T) {
	root := NewDirectory("root", nil)

	// Test directory addition
	result := root.addOrCreateDirectory("subdir")
	if len(root.directories) != 1 || root.directories[0].Name != "subdir" || result.Name != "subdir" {
		// Something went wrong
		t.Error("addOrCreateDirectory(): Couldn't add subdir correctly")
	}

	// Test another directory addition
	result = root.addOrCreateDirectory("subdir2")
	if len(root.directories) != 2 || root.directories[1].Name != "subdir2" || result.Name != "subdir2" {
		// Something went wrong
		t.Error("addOrCreateDirectory(): Couldn't add subdir2 correctly")
	}

	// Test adding the same directory again
	result = root.addOrCreateDirectory("subdir2")
	if len(root.directories) != 2 || root.directories[1].Name != "subdir2" || result.Name != "subdir2" {
		// Something went wrong
		t.Error("addOrCreateDirectory(): Couldn't add subdir2 again correctly")
	}
}

func TestDirectory_AddSourceFileComponents(t *testing.T) {
	root := NewDirectory("root", nil)
	components := []string{"src", "com", "mycompany"}
	root.AddSourceFileComponents(append(components, "App.java"))
	currentDir := root

	// Check created directories
	for _, c := range components {
		if currentDir.directories[0].Name != c {
			t.Errorf("AddSourceFileComponents(): directory %s was not added correctly", c)
		}
		currentDir = currentDir.directories[0]
	}

	// Check created filename
	value, ok := currentDir.files["App.java"]
	if !value || !ok {
		t.Error("AddSourceFileComponents(): file App.java was not added correctly")
	}
}

func TestDirectory_GetMatchingPath(t *testing.T) {
	root := NewDirectory("root", nil)
	components := []string{"subdir", "src", "main", "java", "com", "example", "mypackage", "Util.java"}
	root.AddSourceFileComponents(components)
	partialPath := "com/example/mypackage/Util.java"
	dir, file, err := root.GetMatchingPath(partialPath)

	if dir.Name != "mypackage" || file != "Util.java" || err != nil {
		t.Errorf("GetMatchingPat(): couldn't find %s", partialPath)
	}
}

func TestDirectory_PathRelativeTo(t *testing.T) {
	root := NewDirectory("root", nil)
	components := []string{"subdir", "src", "main", "java", "com", "example", "mypackage", "Util.java"}
	root.AddSourceFileComponents(components)
	src := root.directories[0].directories[0]
	mypackage := src.directories[0].directories[0].directories[0].directories[0].directories[0]

	relativePath := mypackage.PathRelativeTo(src)
	expected := "main/java/com/example/mypackage"

	if relativePath != expected {
		t.Errorf("PathRelativeTo(): expected %s, got %s", expected, relativePath)
	}
}
