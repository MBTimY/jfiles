package project

import (
	"io/ioutil"
	"path/filepath"
	"reflect"
	"testing"

	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/utils"
)

func Test_withCleanup(t *testing.T) {
	// Create test directory
	tempDir, err := ioutil.TempDir("/tmp", "test-")
	if err != nil {
		t.Error("withCleanup() can't set up test directory")
		return
	}

	tempFile, err := ioutil.TempFile(tempDir, "test-")
	if err != nil {
		t.Error("withCleanup() can't set up test file")
		return
	}

	// Create a file in a function wrapped by withCleanup
	_ = withCleanup(tempDir, func() error {
		_, err = ioutil.TempFile(tempDir, "created-")
		if err != nil {
			return err

		}

		return utils.NewRunCmdError(1, "fail")
	})

	// Check that only the test- file remains in the tempDir after execution
	files, err := ioutil.ReadDir(tempDir)

	if len(files) != 1 || files[0].Name() != filepath.Base(tempFile.Name()) {
		// Failed to cleanup
		t.Error("withCleanup() didn't clean up created file.")
		return
	}
}

func Test_deleteEmpty(t *testing.T) {
	want := []string{"aa", "bb", "cc"}
	got := deleteEmpty([]string{"aa", "", "bb", "cc"})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
}
