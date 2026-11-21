package api

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/getkin/kin-openapi/openapi3"
)

// TestOpenAPIMatchesRoutes fails when api/openapi.yaml and the router drift apart: the spec
// must be valid, and its operations must equal the registered routes exactly.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("spec invalid: %v", err)
	}
	spec := map[string]bool{}
	for path, item := range doc.Paths.Map() {
		for method := range item.Operations() {
			spec[strings.ToUpper(method)+" "+path] = true
		}
	}
	s := &Server{Svc: &app.Service{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.Handler()
	// Go patterns use {fp}/{id}; normalize both sides' parameter names.
	norm := regexp.MustCompile(`\{[^}]+\}`)
	routes := map[string]bool{}
	for _, r := range s.Routes() {
		routes[norm.ReplaceAllString(r, "{}")] = true
	}
	specN := map[string]bool{}
	for k := range spec {
		specN[norm.ReplaceAllString(k, "{}")] = true
	}
	var missingInSpec, missingInCode []string
	for r := range routes {
		if !specN[r] {
			missingInSpec = append(missingInSpec, r)
		}
	}
	for r := range specN {
		if !routes[r] {
			missingInCode = append(missingInCode, r)
		}
	}
	sort.Strings(missingInSpec)
	sort.Strings(missingInCode)
	if len(missingInSpec) > 0 {
		t.Errorf("routes not documented in api/openapi.yaml:\n  %s", strings.Join(missingInSpec, "\n  "))
	}
	if len(missingInCode) > 0 {
		t.Errorf("documented operations with no route:\n  %s", strings.Join(missingInCode, "\n  "))
	}
}
