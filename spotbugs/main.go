/*
main implements a Groovy, Graddle, Maven, Ant SAST analyzer, for use alone in your CI jobs or inside the GitLab SAST project
available at https://gitlab.com/gitlab-org/security-products/sast
*/

package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/command"
	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/logutil"
	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/convert"
	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/metadata"
	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/plugin"
)

func main() {
	app := cli.NewApp()
	app.Name = "analyzer"
	app.Version = metadata.AnalyzerVersion
	app.Author = metadata.AnalyzerVendor
	app.Usage = metadata.AnalyzerUsage

	log.SetFormatter(&logutil.Formatter{Project: metadata.AnalyzerName})
	log.Info(metadata.AnalyzerUsage)

	app.Commands = command.NewCommands(command.Config{
		Match:        plugin.Match,
		Analyze:      analyze,
		AnalyzeFlags: analyzeFlags(),
		AnalyzeAll:   true,
		Convert:      convert.Convert,
		Scanner:      metadata.ReportScanner,
		ScanType:     metadata.Type,
	})

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
