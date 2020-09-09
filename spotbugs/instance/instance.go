// Package instance contains the struct type mapping to SpotBugs XML output issue fields.
package instance

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gosimple/slug"
	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/issue"
)

// Instances maps to SpotBugs reports' root XML element.
type Instances struct {
	Instances []Instance `xml:"BugInstance"`
}

// Instance maps to a bug - in our case a vulnerability - in the SpotBugs report.
type Instance struct {
	Type         string `xml:"type,attr"`
	CWEID        int    `xml:"cweid,attr"`
	Rank         int    `xml:"rank,attr"`
	Abbrev       string `xml:"abbrev,attr"`
	Priority     int    `xml:"priority,attr"`
	InstanceHash string `xml:"instanceHash,attr"`
	ShortMessage string `xml:"ShortMessage"`
	LongMessage  string `xml:"LongMessage"`
	Class        struct {
		Name string `xml:"classname,attr"`
	} `xml:"Class"`
	Method struct {
		Name string `xml:"name,attr"`
	} `xml:"Method"`
	SourceLine SourceLine `xml:"SourceLine"` // explicit SourceLine type annotation required to make XML marshaling work
}

// SourceLine maps to a location of a vulnerability (source code file, start line, end line) in the SpotBugs report.
type SourceLine struct {
	Start      int    `xml:"start,attr"`
	End        int    `xml:"end,attr"`
	SourcePath string `xml:"sourcepath,attr"`
}

const (
	spotBugsURL    = "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html#"
	findSecBugsURL = "https://find-sec-bugs.github.io/bugs.htm#"
)

var spotBugsIdentifiers = [...]string{
	"DMI_CONSTANT_DB_PASSWORD",
	"DMI_EMPTY_DB_PASSWORD",
	"HRS_REQUEST_PARAMETER_TO_COOKIE",
	"HRS_REQUEST_PARAMETER_TO_HTTP_HEADER",
	"PT_ABSOLUTE_PATH_TRAVERSAL",
	"PT_RELATIVE_PATH_TRAVERSAL",
	"SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE",
	"SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING",
	"XSS_REQUEST_PARAMETER_TO_JSP_WRITER",
	"XSS_REQUEST_PARAMETER_TO_SEND_ERROR",
	"XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER",
}

// isSpotBugsIdentifer returns true if bug instance has SpotBugsIdentifier
func (bug Instance) isSpotBugsIdentifer() bool {
	for _, item := range spotBugsIdentifiers {
		if item == bug.Type {
			return true
		}
	}
	return false
}

// CompareKey returns a string used to establish whether two issues are the same.
func (bug Instance) CompareKey() string {
	fields := []string{
		bug.InstanceHash,
		bug.Type,
		bug.SourceLine.SourcePath,
		strconv.Itoa(bug.SourceLine.Start),
	}

	key := strings.Join(fields, ":")

	if key == ":::0" {
		return ""
	}

	return key
}

// Severity returns the normalized Severity of the issue.
// See https://github.com/spotbugs/spotbugs/blob/3.1.1/spotbugs/src/main/java/edu/umd/cs/findbugs/BugRankCategory.java#L32
func (bug Instance) Severity() issue.SeverityLevel {
	switch bug.Rank {
	case 1, 2, 3, 4:
		return issue.SeverityLevelCritical
	case 5, 6, 7, 8, 9:
		return issue.SeverityLevelHigh
	case 10, 11, 12, 13, 14:
		return issue.SeverityLevelMedium
	case 15, 16, 17, 18, 19, 20:
		return issue.SeverityLevelLow
	}
	return issue.SeverityLevelUnknown
}

// Confidence returns the normalized Confidence of the issue.
// See https://github.com/spotbugs/spotbugs/blob/3.1.1/spotbugs/src/main/java/edu/umd/cs/findbugs/Priorities.java
func (bug Instance) Confidence() issue.ConfidenceLevel {
	switch bug.Priority {
	case 1:
		return issue.ConfidenceLevelHigh
	case 2:
		return issue.ConfidenceLevelMedium
	case 3:
		return issue.ConfidenceLevelLow
	case 4:
		return issue.ConfidenceLevelExperimental
	case 5:
		return issue.ConfidenceLevelIgnore
	}
	return issue.ConfidenceLevelUnknown
}

// Location returns a structured Location.
func (bug Instance) Location(prependPath string) issue.Location {
	return issue.Location{
		File:      filepath.Join(prependPath, bug.SourceLine.SourcePath),
		LineStart: bug.SourceLine.Start,
		LineEnd:   bug.SourceLine.End,
		Class:     bug.Class.Name,
		Method:    bug.Method.Name,
	}
}

// Identifiers returns the normalized Identifiers of the issue.
func (bug Instance) Identifiers() []issue.Identifier {
	identifiers := []issue.Identifier{
		bug.fSBIdentifier(),
	}

	// Add CWE ID
	if bug.CWEID != 0 {
		identifiers = append(identifiers, issue.CWEIdentifier(bug.CWEID))
	}

	return identifiers
}

// fSBIdentifier returns a structured Identifier for a FSB bug Type
func (bug Instance) fSBIdentifier() issue.Identifier {
	return issue.Identifier{
		Type:  "find_sec_bugs_type",
		Name:  fmt.Sprintf("Find Security Bugs-%s", bug.Type),
		Value: bug.Type,
		URL:   bug.bugURL(),
	}
}

// bugURL returns url for bug description
func (bug Instance) bugURL() string {
	if bug.isSpotBugsIdentifer() {
		return fmt.Sprintf("%s%s", spotBugsURL, bug.slugify())
	}
	return fmt.Sprintf("%s%s", findSecBugsURL, bug.Type)
}

// slugify returns slug for a bug instance
func (bug Instance) slugify() string {
	sluggedBugType := strings.ReplaceAll(bug.Type, "_", "-")
	return slug.Make(fmt.Sprintf("%s-%s-%s", bug.Abbrev, bug.ShortMessage, sluggedBugType))
}

// By is a type that supports sorting.
// Example usage:
// buginstance.By(fileName).Sort(finalReport.Instances)
// which sorts by filename.
type By func(b1, b2 *Instance) bool

// Sort is a function that sorts bugInstances
func (by By) Sort(bugInstances []Instance) {
	bs := &bugInstanceSorter{
		bugInstances: bugInstances,
		by:           by,
	}
	sort.Sort(bs)
}

type bugInstanceSorter struct {
	bugInstances []Instance
	by           func(b1, b2 *Instance) bool
}

func (b *bugInstanceSorter) Len() int {
	return len(b.bugInstances)
}

func (b *bugInstanceSorter) Swap(i, j int) {
	b.bugInstances[i], b.bugInstances[j] = b.bugInstances[j], b.bugInstances[i]
}

func (b *bugInstanceSorter) Less(i, j int) bool {
	return b.by(&b.bugInstances[i], &b.bugInstances[j])
}
