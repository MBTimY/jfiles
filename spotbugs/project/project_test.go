package project

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFindProjects(t *testing.T) {
	projects, err := FindProjects(filepath.Join("..", "test", "fixtures"), true)
	if err != nil {
		t.Errorf("%s\n", err.Error())
	}

	if len(projects) != 12 {
		t.Errorf("%d projects found, wanted 12.", len(projects))
	}
}

func TestNewProject(t *testing.T) {
	emptyPath := filepath.Join("..", "test", "empty")
	projectPath := filepath.Join("..", "test", "fixtures", "maven-project")
	type args struct {
		path string
	}
	tests := []struct {
		name        string
		args        args
		wantBuilder string
		wantErr     bool
	}{
		{
			name: "Empty",
			args: args{
				path: emptyPath,
			},
			wantBuilder: "",
			wantErr: true,

		},
		{
			name: "Project",
			args: args{
				path: projectPath,
			},
			wantBuilder: "Maven",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := newProject(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("newProject() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if _, ok := err.(errNoCompatibleBuilder) ; !ok {
					t.Errorf(
						"newProject() error type = %s, wanted error type errNoCompatibleBuilder",
						reflect.TypeOf(err))
					return
				}
			} else {
				if p.builder.name != tt.wantBuilder {
					t.Errorf(
						"newProject() detected builder is wrong wanted %s got %s",
						tt.wantBuilder,
						p.builder.name)
					return
				}
			}
		})
	}
}

func TestProject_Packages(t *testing.T) {
	tests := []struct {
		name        string
		projectPath string
		want        []string
	}{
		{
			name:        "Groovy",
			projectPath: filepath.Join("..", "test", "fixtures", "groovy-project"),
			want:        []string{"com.gitlab.security_products.tests"},
		},
		{
			name:        "Java",
			projectPath: filepath.Join("..", "test", "fixtures", "maven-project"),
			want:        []string{"com.gitlab.security_products.tests"},
		},
		{
			name:        "Scala",
			projectPath: filepath.Join("..", "test", "fixtures", "sbt-project"),
			want:        []string{"com.example"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := newProject(tt.projectPath)
			if err != nil {
				t.Errorf("%s\n", err.Error())
				return
			}

			if got := p.Packages(); !reflect.DeepEqual(got, tt.want) {
				absPath, err := filepath.Abs(tt.projectPath)
				if err != nil {
					cur, _ := os.Getwd()
					t.Errorf("Project.Packages() no absolute path exist for %s (current dir: %s )", tt.projectPath, cur)
				}
				t.Errorf("Project.Packages() for %s = %v, want %v", absPath, got, tt.want)
			}
		})
	}
}

func TestProject_GetSourcePathRelativeToProject(t *testing.T) {
	tests := []struct {
		name         string
		projectPath  string
		reportedPath string
		wantResult   string
		wantErr      bool
	}{
		{
			name:         "Groovy",
			projectPath:  filepath.Join("..", "test", "fixtures", "groovy-project"),
			reportedPath: "com/gitlab/security_products/tests/App.groovy",
			wantResult:   "src/main/groovy/com/gitlab/security_products/tests/App.groovy",
			wantErr:      false,
		},
		{
			name:         "Java",
			projectPath:  filepath.Join("..", "test", "fixtures", "maven-project"),
			reportedPath: "com/gitlab/security_products/tests/App.java",
			wantResult:   "src/main/java/com/gitlab/security_products/tests/App.java",
			wantErr:      false,
		},
		{
			name:         "Scala",
			projectPath:  filepath.Join("..", "test", "fixtures", "sbt-project"),
			reportedPath: "com/example/Main.scala",
			wantResult:   "src/main/scala/com/example/Main.scala",
			wantErr:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := newProject(tt.projectPath)
			if err != nil {
				t.Errorf("%s\n", err.Error())
				return
			}

			absPath, err := filepath.Abs(tt.projectPath)
			if err != nil {
				cur, _ := os.Getwd()
				t.Errorf("Project.Packages() no absolute path exist for %s (current dir: %s )", tt.projectPath, cur)
			}

			gotResult, err := p.RelativePath(tt.reportedPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("Project.RelativePath() for %s error = %v, wantErr %v", absPath, err, tt.wantErr)
				return
			}
			if gotResult != tt.wantResult {
				t.Errorf("Project.RelativePath() for %s = %v, want %v", absPath, gotResult, tt.wantResult)
			}
		})
	}
}
