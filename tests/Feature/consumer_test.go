package feature_test

import (
	"testing"

	"github.com/arandu-io/framework/view"

	webhook "github.com/hyz-is/arandu-webhook"
)

// TestTheModuleBuildsBesideTheFrameworkViews holds the dependency floor an
// installer gets. An application that installs this module almost always draws
// pages with framework/view, and that package converts hesape's view.Page to
// its own: a hesape this module required beyond what the framework was built
// against would stop every such application compiling, in its own repository.
//
// The assertion is that this file compiles. It imports the view package
// against the same build list an installer resolves, so raising the hesape
// requirement past what framework/view accepts fails here first.
func TestTheModuleBuildsBesideTheFrameworkViews(t *testing.T) {
	t.Parallel()

	var page view.Page
	if page.Title != "" {
		t.Fatalf("the zero page has the title %q", page.Title)
	}
	if webhook.DefaultPrefix == "" {
		t.Fatal("the module has no default prefix")
	}
}
