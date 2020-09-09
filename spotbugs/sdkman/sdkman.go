package sdkman

import (
	"fmt"
	"os/exec"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	// FlagJavaPath is the name of spotbug's cli java path argument
	FlagJavaPath = "javaPath"
	// FlagJavaVersion is the name of spotbug's cli java version argument
	FlagJavaVersion = "javaVersion"
	// FlagJava8Version is the name of spotbug's cli java 8 version argument
	FlagJava8Version = "java8Version"
	// FlagJava11Version is the name of spotbug's cli java 11 version argument
	FlagJava11Version = "java11Version"
	// FlagSdkmanDir is the name of spotbug's cli sdkman argument
	FlagSdkmanDir = "sdkmanDir"
)

// SetupSystemJava sets up the system so that SpotBugs and it's dependencies (e.g. Maven) use the same Java
func SetupSystemJava(c *cli.Context) {
	if usesCustomJavaPath(c) {
		return
	}

	sdkmanDir := c.String(FlagSdkmanDir)
	javaVersion := selectedSystemJava(c)

	cmd := exec.Command(
		"/bin/bash",
		"-c",
		fmt.Sprintf("source %[1]s/bin/sdkman-init.sh"+
			// can exit 1 if already installed
			" && (sdk list java | grep -qv \"installed.*%[2]s\" || sdk install java %[2]s)"+
			" && sdk default java %[2]s", sdkmanDir, javaVersion))
	output, err := cmd.CombinedOutput()

	log.Debugf("%s\n%s", cmd.String(), output)

	if err != nil {
		log.Warnf("Failed to set system Java: %s\n", err.Error())

		return
	}
}

// JavaPath determines the path to the java executable
func JavaPath(c *cli.Context) string {
	if usesCustomJavaPath(c) {
		return c.String(FlagJavaPath)
	}

	return filepath.FromSlash(fmt.Sprintf("%s/candidates/java/current/bin/java", c.String(FlagSdkmanDir)))
}

// returns based on whether or not using a custom Java
func usesCustomJavaPath(c *cli.Context) bool {
	return c.String(FlagJavaPath) != "java" && c.String(FlagJavaPath) != ""
}

// determine the version of the selected Java to use
func selectedSystemJava(c *cli.Context) string {
	switch c.String(FlagJavaVersion) {
	case "11":
		return c.String(FlagJava11Version)
	case "8":
		return c.String(FlagJava8Version)
	default:
		log.Warnf(
			"Java version %s is not supported. Valid values are 8, 11. Using Java 8.\n",
			c.String(FlagJavaVersion))
		return c.String(FlagJava8Version)
	}
}
