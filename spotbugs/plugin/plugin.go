package plugin

import (
	"os"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/plugin"

	"gitlab.com/gitlab-org/security-products/analyzers/spotbugs/v2/project"
)

var isMatchingDone = false
var isMatching = false

// Match checks if this project can be built by one of our supported builders:
func Match(path string, info os.FileInfo) (bool, error) {
	return project.HasBuilder(info), nil
}

func init() {
	plugin.Register("spotbugs", Match)
}
