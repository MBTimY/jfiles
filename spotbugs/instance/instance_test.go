package instance

import (
	"reflect"
	"testing"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/issue"
)

func TestBugInstance_CompareKey(t *testing.T) {
	tests := []struct {
		name         string
		instanceHash string
		instanceType string
		sourcePath   string
		startLine    int
		want         string
	}{
		{
			name:         "Good",
			instanceHash: "abcdef1234567890",
			instanceType: "find_sec_bugs_type",
			sourcePath:   "gradle/src/main/java/com/gitlab/security_products/tests/App.java",
			startLine:    29,
			want:         "abcdef1234567890:find_sec_bugs_type:gradle/src/main/java/com/gitlab/security_products/tests/App.java:29",
		},
		{
			name:         "Missing InstanceHash",
			instanceType: "find_sec_bugs_type",
			sourcePath:   "gradle/src/main/java/com/gitlab/security_products/tests/App.java",
			startLine:    29,
			want:         ":find_sec_bugs_type:gradle/src/main/java/com/gitlab/security_products/tests/App.java:29",
		},
		{
			name:         "Missing Type",
			instanceHash: "abcdef1234567890",
			sourcePath:   "gradle/src/main/java/com/gitlab/security_products/tests/App.java",
			startLine:    29,
			want:         "abcdef1234567890::gradle/src/main/java/com/gitlab/security_products/tests/App.java:29",
		},
		{
			name:         "Missing SourcePath",
			instanceHash: "abcdef1234567890",
			instanceType: "find_sec_bugs_type",
			startLine:    29,
			want:         "abcdef1234567890:find_sec_bugs_type::29",
		},
		{
			name:         "Missing Start",
			instanceHash: "abcdef1234567890",
			instanceType: "find_sec_bugs_type",
			sourcePath:   "gradle/src/main/java/com/gitlab/security_products/tests/App.java",
			want:         "abcdef1234567890:find_sec_bugs_type:gradle/src/main/java/com/gitlab/security_products/tests/App.java:0",
		},
		{
			name: "All missing",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bug := Instance{
				InstanceHash: tt.instanceHash,
				Type:         tt.instanceType,
				SourceLine: SourceLine{
					Start:      tt.startLine,
					SourcePath: tt.sourcePath,
				},
			}
			if got := bug.CompareKey(); got != tt.want {
				t.Errorf("Instance.CompareKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBugInstance_Location(t *testing.T) {
	type args struct {
		prependPath string
	}
	tests := []struct {
		name       string
		sourcePath string
		start      int
		end        int
		class      string
		method     string
		args       args
		want       issue.Location
	}{
		{
			name:       "Location",
			sourcePath: "src/main/java/com/example/App.java",
			start:      4,
			end:        6,
			class:      "App",
			method:     "main",
			args: args{
				prependPath: "myproject",
			},
			want: issue.Location{
				File:      "myproject/src/main/java/com/example/App.java",
				LineStart: 4,
				LineEnd:   6,
				Class:     "App",
				Method:    "main",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bug := Instance{}
			bug.Class.Name = tt.class
			bug.Method.Name = tt.method
			bug.SourceLine.Start = tt.start
			bug.SourceLine.End = tt.end
			bug.SourceLine.SourcePath = tt.sourcePath

			if got := bug.Location(tt.args.prependPath); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Instance.Location() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBugInstance_Identifiers(t *testing.T) {
	tests := []struct {
		name         string
		bugType      string
		cweid        int
		abbrev       string
		shortMessage string
		want         []issue.Identifier
	}{
		{
			name:         "Identifier",
			bugType:      "SERVLET_PARAMETER",
			cweid:        70,
			abbrev:       "",
			shortMessage: "",
			want: []issue.Identifier{
				{
					Type:  "find_sec_bugs_type",
					Name:  "Find Security Bugs-SERVLET_PARAMETER",
					Value: "SERVLET_PARAMETER",
					URL:   "https://find-sec-bugs.github.io/bugs.htm#SERVLET_PARAMETER",
				},
				{
					Type:  "cwe",
					Name:  "CWE-70",
					Value: "70",
					URL:   "https://cwe.mitre.org/data/definitions/70.html",
				},
			},
		},
		{
			name:         "Identifier",
			bugType:      "XSS_REQUEST_PARAMETER_TO_SEND_ERROR",
			cweid:        70,
			abbrev:       "xss",
			shortMessage: "Servlet reflected cross site scripting vulnerability in error page",
			want: []issue.Identifier{
				{
					Type:  "find_sec_bugs_type",
					Name:  "Find Security Bugs-XSS_REQUEST_PARAMETER_TO_SEND_ERROR",
					Value: "XSS_REQUEST_PARAMETER_TO_SEND_ERROR",
					URL:   "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html#xss-servlet-reflected-cross-site-scripting-vulnerability-in-error-page-xss-request-parameter-to-send-error",
				},
				{
					Type:  "cwe",
					Name:  "CWE-70",
					Value: "70",
					URL:   "https://cwe.mitre.org/data/definitions/70.html",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bug := Instance{
				Type:         tt.bugType,
				CWEID:        tt.cweid,
				Abbrev:       tt.abbrev,
				ShortMessage: tt.shortMessage,
			}
			if got := bug.Identifiers(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Instance.Identifiers() = %v, want %v", got, tt.want)
			}
		})
	}
}
