package utils

import (
	"os"
	"os/exec"
	"testing"

	"github.com/urfave/cli"
)

func TestRunCmdWithTextErrorDetection(t *testing.T) {
	type args struct {
		cmd       *exec.Cmd
		errorText string
		message   string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Command success",
			args: args{
				cmd:       exec.Command("true"),
				errorText: "errorText",
				message:   "",
			},
			wantErr: false,
		},
		{
			name: "Command fails by text",
			args: args{
				cmd:       exec.Command("echo", "errorText"),
				errorText: "errorText",
				message:   "",
			},
			wantErr: true,
		},
		{
			name: "Command fails by exit code",
			args: args{
				cmd:       exec.Command("false"),
				errorText: "errorText",
				message:   "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		c := &cli.Context{
			App: &cli.App{
				Writer: os.Stdout,
			},
		}
		t.Run(tt.name, func(t *testing.T) {
			err := RunCmdWithTextErrorDetection(tt.args.cmd, c, tt.args.errorText, tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("RunCmdWithTextErrorDetection() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
