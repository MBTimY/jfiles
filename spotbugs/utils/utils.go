package utils

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

// RunCmdError are errors for cmd runs that include an exit code
type RunCmdError struct {
	err      string
	exitCode int
}

// NewRunCmdError returns a new run command error
func NewRunCmdError(exitCode int, message string) error {
	return &RunCmdError{
		err:      message,
		exitCode: exitCode,
	}
}

func (e *RunCmdError) Error() string {
	return e.err
}

// RunCmd runs a command and gets the exit code.
func RunCmd(cmd *exec.Cmd) error {
	output, err := cmd.CombinedOutput()
	log.Debugf("%s\n%s", cmd.String(), output)

	if err != nil {
		switch err.(type) {
		case *exec.ExitError:
			// The command failed during its execution
			exitError := err.(*exec.ExitError)
			waitStatus := exitError.Sys().(syscall.WaitStatus)
			return NewRunCmdError(waitStatus.ExitStatus(), err.Error())
		default:
			// The command couldn't even be executed
			return NewRunCmdError(1, fmt.Sprintf("Command couldn't be executed: %v", err))
		}
	}

	waitStatus := cmd.ProcessState.Sys().(syscall.WaitStatus)
	exitStatus := waitStatus.ExitStatus()

	if exitStatus != 0 {
		return NewRunCmdError(exitStatus, "Command returned a non zero exit status")
	}

	return nil
}

// RunCmdWithTextErrorDetection runs a command and returns an error code according to the presence
// of a string in the output.
// Uses code from https://github.com/kjk/go-cookbook in the public domain
func RunCmdWithTextErrorDetection(cmd *exec.Cmd, c *cli.Context, errorText string, message string) error {
	output, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	// Print output
	log.Debugf("%s\n%s", cmd.String(), output)

	// Detect error string
	if strings.Index(string(output), errorText) != -1 {
		// Error text is present, return error.
		return errors.New(message)
	}

	return nil
}

// SetupCmdNoStd sets up a command's directory and environment for execution.
func SetupCmdNoStd(projectPath string, cmd *exec.Cmd) *exec.Cmd {
	cmd.Dir = projectPath
	cmd.Env = os.Environ()
	return cmd
}

// WithWarning runs the function passed as argument and prints a warning if it returns an error
func WithWarning(warning string, fun func() error) {
	err := fun()
	if err != nil {
		log.Warnf("%s (%s)\n", warning, err.Error())
	}
}
