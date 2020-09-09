package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/command"
	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/issue"
	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/project"
)

func mockMatch(path string, info os.FileInfo) (bool, error) {
	return true, nil
}

func mockConvert(reader io.Reader, prependPath string) (*issue.Report, error) {
	return &issue.Report{}, nil
}

func newMockApp() *cli.App {
	app := cli.NewApp()
	app.Commands = command.NewCommands(command.Config{
		Match:        mockMatch,
		Analyze:      analyze,
		AnalyzeFlags: analyzeFlags(),
		Convert:      mockConvert,
	})

	return app
}

func TestAnalyze(t *testing.T) {
	path := "/tmp"

	app := *newMockApp()
	set := flag.NewFlagSet("javaPath", 0)
	c := *cli.NewContext(&app, set, nil)

	want := ioutil.NopCloser(bytes.NewReader(([]byte("<Instances></Instances>"))))

	got, err := analyze(&c, path)
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, want, got)
}

func TestAnalyzeNoCompile(t *testing.T) {
	path := "/tmp"

	app := *newMockApp()
	set := flag.NewFlagSet("javaPath", 0)
	c := *cli.NewContext(&app, set, nil)

	set.Bool("compile", false, "compile stuff")

	// We override compile to ensure it is not executed,
	oldCompile := compileProj
	defer func() { compileProj = oldCompile }()

	panicCompile := func(c *cli.Context, projects []project.Project, failNever bool) error {
		return fmt.Errorf("compile should not be called")
	}
	compileProj = panicCompile

	want := ioutil.NopCloser(bytes.NewReader(([]byte("<Instances></Instances>"))))

	got, err := analyze(&c, path)
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, want, got)
}
