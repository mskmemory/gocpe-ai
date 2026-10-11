package service_test

import (
	"context"
	"encoding/json"
	"github.com/mskmemory/gocpe-ai/internal/service"
	"github.com/mskmemory/gocpe-ai/internal/testutil"
	"strings"
	"testing"
)

func sbomRequest(format string, doc any) []byte {
	b, _ := json.Marshal(map[string]any{"input": map[string]any{"kind": "sbom", "format": format, "document": doc}, "options": map[string]any{"provider": "openai", "model": "test-model"}})
	return b
}
func TestCycloneDXTraversal(t *testing.T) {
	for _, version := range []string{"1.5", "1.6"} {
		t.Run(version, func(t *testing.T) {
			m := testutil.NewStore()
			s := newService(t, m, nil)
			doc := map[string]any{"bomFormat": "CycloneDX", "specVersion": version, "version": 1, "metadata": map[string]any{"component": map[string]any{"type": "application", "name": "Root", "bom-ref": "root"}}, "components": []any{map[string]any{"type": "library", "name": "log4j-core", "group": "org.apache.logging.log4j", "version": "2.17.1", "supplier": map[string]any{"name": "Apache"}, "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1", "components": []any{map[string]any{"type": "library", "name": "Nested"}}}}}
			j, e := s.Create(context.Background(), "a", "resolution", "", sbomRequest("cyclonedx", doc))
			if e != nil {
				t.Fatal(e)
			}
			a := m.Admission(j.ID)
			if len(a.Components) != 3 {
				t.Fatalf("got %d", len(a.Components))
			}
			if a.Components[1].Package.Vendor != "Apache" || a.Components[1].Package.Namespace != "org.apache.logging.log4j" {
				t.Fatal(a.Components[1])
			}
			if !strings.HasSuffix(a.Components[2].SourcePointer, "/components/0/components/0") || !strings.HasPrefix(a.Components[2].Package.ID, "generated-") {
				t.Fatal(a.Components[2])
			}
			again, e := s.Create(context.Background(), "a", "resolution", "", sbomRequest("cyclonedx", doc))
			if e != nil || m.Admission(again.ID).Components[2].Package.ID != a.Components[2].Package.ID {
				t.Fatal("unstable generated ID", e)
			}
		})
	}
}
func spdxDocument() map[string]any {
	return map[string]any{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "Test SBOM", "documentNamespace": "https://example.com/spdx/test", "creationInfo": map[string]any{"creators": []any{"Tool: test"}, "created": "2026-10-10T00:00:00Z"}, "packages": []any{map[string]any{"SPDXID": "SPDXRef-A", "name": "A", "downloadLocation": "NOASSERTION", "supplier": "Organization: Apache", "externalRefs": []any{map[string]any{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/example"}}}}}
}
func TestSPDXParsingAndInvalidSBOM(t *testing.T) {
	m := testutil.NewStore()
	s := newService(t, m, nil)
	doc := spdxDocument()
	j, e := s.Create(context.Background(), "a", "resolution", "", sbomRequest("spdx", doc))
	if e != nil {
		t.Fatal(e)
	}
	a := m.Admission(j.ID)
	if a.Components[0].Package.Vendor != "Apache" || a.Components[0].Package.ExistingPURLs[0] != "pkg:npm/example" {
		t.Fatal(a)
	}
	cases := []struct {
		name, format string
		doc          map[string]any
	}{
		{"missing_required", "spdx", map[string]any{"spdxVersion": "SPDX-2.3"}},
		{"unsupported_version", "cyclonedx", map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1}},
		{"bad_component_type", "cyclonedx", map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []any{map[string]any{"type": "not-real", "name": "A"}}}},
		{"empty", "cyclonedx", map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}},
		{"duplicate_id", "cyclonedx", map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []any{map[string]any{"type": "library", "name": "A", "bom-ref": "same"}, map[string]any{"type": "library", "name": "B", "bom-ref": "same"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, e := s.Create(context.Background(), "a", "resolution", "", sbomRequest(tc.format, tc.doc))
			expectCode(t, e, "INVALID_INPUT")
		})
	}
}
func TestSBOMComponentLimit(t *testing.T) {
	s := newService(t, testutil.NewStore(), nil)
	components := []any{}
	for i := 0; i < service.MaxComponents+1; i++ {
		components = append(components, map[string]any{"type": "library", "name": "A"})
	}
	doc := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}
	_, e := s.Create(context.Background(), "a", "resolution", "", sbomRequest("cyclonedx", doc))
	expectCode(t, e, "INVALID_INPUT")
}
