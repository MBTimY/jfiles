// Package convert translates a SpotBugs XML report into a issue.Report.
package convert

import (
	"encoding/xml"
	"io"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/issue"
	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/instance"
	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/metadata"
)

// Convert translate a SpotBugs XML report into a issue.Report.
func Convert(reader io.Reader, prependPath string) (*issue.Report, error) {
	var doc = struct {
		BugInstances []instance.Instance `xml:"BugInstance"`
	}{}

	err := xml.NewDecoder(reader).Decode(&doc)
	if err != nil {
		return nil, err
	}

	issues := make([]issue.Issue, len(doc.BugInstances))
	for i, bug := range doc.BugInstances {
		issues[i] = issue.Issue{
			Category:    metadata.Type,
			Scanner:     metadata.IssueScanner,
			Name:        bug.ShortMessage,
			Message:     bug.ShortMessage,
			Description: bug.LongMessage, // Could be extracted from BugPattern/Details instead
			CompareKey:  bug.CompareKey(),
			Severity:    bug.Severity(),
			Confidence:  bug.Confidence(),
			// Solution: bug.Solution(), Need to parse BugPattern/Details to extract solution
			Location:    bug.Location(prependPath),
			Identifiers: bug.Identifiers(),
			// Links:    bug.Links(), Need to parse BugPattern/Details to extract links
		}
	}

	var report = issue.NewReport()
	report.Vulnerabilities = issues
	return &report, nil
}
