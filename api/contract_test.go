package api_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/mskmemory/gocpe-ai/api"
	"testing"
)

func TestContractAndExamples(t *testing.T) {
	doc, e := api.Load()
	if e != nil {
		t.Fatal(e)
	}
	ids := map[string]bool{}
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if ids[op.OperationID] {
				t.Fatal("duplicate operation ID")
			}
			ids[op.OperationID] = true
			if op.RequestBody != nil {
				for _, content := range op.RequestBody.Value.Content {
					if content.Example != nil {
						if e := content.Schema.Value.VisitJSON(content.Example); e != nil {
							t.Fatalf("%s %s example: %v", method, path, e)
						}
					}
				}
			}
		}
	}
	if len(ids) != 9 {
		t.Fatalf("expected 9 operations, got %d", len(ids))
	}
}
func TestVendoredSchemaChecksums(t *testing.T) {
	b, e := api.Files.ReadFile("schemas/manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	var entries []struct{ File, Source, SHA256 string }
	if e = json.Unmarshal(b, &entries); e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		b, e := api.Files.ReadFile("schemas/" + entry.File)
		if e != nil {
			t.Fatal(e)
		}
		hash := sha256.Sum256(b)
		if hex.EncodeToString(hash[:]) != entry.SHA256 {
			t.Fatal("schema checksum changed", entry.File)
		}
	}
}
