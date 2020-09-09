package metadata_test

import (
	"reflect"
	"testing"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/issue"
	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/metadata"
)

func TestReportScanner(t *testing.T) {
	want := issue.ScannerDetails{
		ID:      "find_sec_bugs",
		Name:    "Find Security Bugs",
		Version: metadata.ScannerVersion,
		Vendor: issue.Vendor{
			Name: "GitLab",
		},
		URL: "https://spotbugs.github.io",
	}
	got := metadata.ReportScanner

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
}
