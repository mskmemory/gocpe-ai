package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/mskmemory/gocpe-ai/api"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const MaxBodyBytes = 10 << 20
const MaxComponents = 1000
const MaxDepth = 64

type Validator struct {
	Contract *openapi3.T
	sbom     map[string]*jsonschema.Schema
}
type offlineLoader struct{}

func (offlineLoader) Load(string) (any, error) { return nil, fmt.Errorf("schema is not embedded") }
func NewValidator() (*Validator, error) {
	doc, err := api.Load()
	if err != nil {
		return nil, err
	}
	v := &Validator{Contract: doc, sbom: map[string]*jsonschema.Schema{}}
	for _, version := range []string{"1.5", "1.6", "spdx"} {
		c := jsonschema.NewCompiler()
		c.UseLoader(offlineLoader{})
		c.AssertFormat()
		files := []string{"bom-" + version + ".schema.json", "spdx.schema.json", "jsf-0.82.schema.json"}
		root := "http://cyclonedx.org/schema/" + files[0]
		if version == "spdx" {
			files = []string{"spdx-2.3.schema.json"}
			root = "http://spdx.org/rdf/terms/2.3"
		}
		for _, name := range files {
			actual := name
			if name == "spdx.schema.json" && version == "1.5" {
				actual = "spdx-licenses-1.5.schema.json"
			}
			b, e := api.Files.ReadFile("schemas/" + actual)
			if e != nil {
				return nil, e
			}
			resource, e := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if e != nil {
				return nil, e
			}
			id := resource.(map[string]any)["$id"].(string)
			if e = c.AddResource(id, resource); e != nil {
				return nil, e
			}
		}
		schema, e := c.Compile(root)
		if e != nil {
			return nil, e
		}
		v.sbom[version] = schema
	}
	return v, nil
}

type Prepared struct {
	Options    Options
	Kind       string
	Components []Component
	Canonical  []byte
}

// ParseJSON rejects duplicate keys, invalid UTF-8, trailing documents and excess depth.
// Keep json.Number so the input hash never merges different large integer values.
func ParseJSON(raw []byte) (any, error) {
	if len(raw) > MaxBodyBytes {
		return nil, &Fault{Status: 413, Code: "PAYLOAD_TOO_LARGE", Message: "Body exceeds 10 MiB"}
	}
	bad := &Fault{Status: 400, Code: "INVALID_JSON", Message: "Expected a single UTF-8 JSON document without duplicate keys"}
	if !utf8.Valid(raw) {
		return nil, bad
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > MaxDepth {
			return nil, Invalid("", "JSON nesting exceeds 64")
		}
		t, e := d.Token()
		if e != nil {
			return nil, bad
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return t, nil
		}
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				t, e := d.Token()
				if e != nil {
					return nil, bad
				}
				k, ok := t.(string)
				if !ok {
					return nil, bad
				}
				if _, exists := m[k]; exists {
					return nil, bad
				}
				x, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				m[k] = x
			}
			t, e = d.Token()
			if e != nil || t != json.Delim('}') {
				return nil, bad
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				x, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				a = append(a, x)
			}
			t, e = d.Token()
			if e != nil || t != json.Delim(']') {
				return nil, bad
			}
			return a, nil
		default:
			return nil, bad
		}
	}
	v, e := read(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, bad
	}
	return v, nil
}
func (v *Validator) CheckSchema(name string, value any) error {
	// kin-openapi expects floating-point JSON numbers, while canonicalization retains exact numbers.
	b, _ := json.Marshal(value)
	var compatible any
	if json.Unmarshal(b, &compatible) != nil {
		return Invalid("", "Invalid JSON number")
	}
	if err := v.Contract.Components.Schemas[name].Value.VisitJSON(compatible); err != nil {
		pointer := ""
		var se *openapi3.SchemaError
		if errors.As(err, &se) {
			for _, p := range se.JSONPointer() {
				pointer += "/" + strings.ReplaceAll(strings.ReplaceAll(p, "~", "~0"), "/", "~1")
			}
		}
		return Invalid(pointer, "Does not match the API schema")
	}
	return nil
}
func (v *Validator) Prepare(entry string, raw []byte) (Prepared, error) {
	var p Prepared
	value, err := ParseJSON(raw)
	if err != nil {
		return p, err
	}
	schema := "CreateResolution"
	if entry == "package_search" {
		schema = "PackageSearchRequest"
	} else if entry != "resolution" {
		return p, Invalid("", "Unknown entrypoint")
	}
	if err = v.CheckSchema(schema, value); err != nil {
		return p, err
	}
	p.Canonical, _ = json.Marshal(value)
	// JSON Schema permits integral numbers such as 1.0. Normalize only the typed
	// decoding representation; the original value remains intact for hashes/SBOM.
	var typedValue any
	if err = json.Unmarshal(raw, &typedValue); err != nil {
		return p, Invalid("", "Unsupported JSON number")
	}
	typedJSON, err := json.Marshal(typedValue)
	if err != nil {
		return p, Invalid("", "Invalid typed input")
	}

	if entry == "package_search" {
		var req PackageSearchRequest
		if err = json.Unmarshal(typedJSON, &req); err != nil {
			return p, Invalid("", "Invalid typed input")
		}
		p.Options = req.Options
		p.Kind = "packages"
		pkg := Package{ID: "component-1", Name: req.Name, Vendor: req.Vendor, Version: req.Version, Ecosystem: req.Ecosystem, Namespace: req.Namespace, RepositoryURLs: req.RepositoryURLs, ExistingCPEs: req.ExistingCPEs, ExistingPURLs: req.ExistingPURLs}
		if strings.TrimSpace(pkg.Vendor) == "" {
			return p, Invalid("/vendor", "Vendor must not be blank")
		}
		p.Components = []Component{{Package: pkg, SourcePointer: "", RawValues: append(json.RawMessage(nil), raw...)}}
	} else {
		var req CreateResolution
		if err = json.Unmarshal(typedJSON, &req); err != nil {
			return p, Invalid("", "Invalid typed input")
		}
		p.Options = req.Options
		var in Input
		_ = json.Unmarshal(req.Input, &in)
		p.Kind = in.Kind
		if in.Kind == "packages" {
			for i, pkg := range in.Packages {
				original := value.(map[string]any)["input"].(map[string]any)["packages"].([]any)[i]
				b, _ := json.Marshal(original)
				p.Components = append(p.Components, Component{Package: pkg, Ordinal: i, SourcePointer: fmt.Sprintf("/input/packages/%d", i), RawValues: b})
			}
		}
		if in.Kind == "sbom" {
			doc := value.(map[string]any)["input"].(map[string]any)["document"].(map[string]any)
			p.Components, err = v.parseSBOM(in.Format, doc)
			if err != nil {
				return p, err
			}
		}
	}
	if len(p.Components) == 0 || len(p.Components) > MaxComponents {
		return p, Invalid("/input", "Expected 1 to 1000 components")
	}
	ids := map[string]bool{}
	for i := range p.Components {
		c := &p.Components[i]
		c.Ordinal = i
		if ids[c.Package.ID] {
			return p, Invalid(c.SourcePointer, "Duplicate component ID")
		}
		ids[c.Package.ID] = true
		pointer := c.SourcePointer
		if entry == "package_search" {
			pointer = ""
		}
		if err = v.checkPackage(c.Package, pointer); err != nil {
			return p, err
		}
	}
	if p.Options.Targets == nil {
		p.Options.Targets = []string{"cpe", "purl"}
	}
	if p.Options.MaxCandidates == 0 {
		p.Options.MaxCandidates = 5
	}
	return p, nil
}
func (v *Validator) checkPackage(p Package, pointer string) error {
	if strings.TrimSpace(p.Name) == "" {
		return Invalid(pointer+"/name", "Name must not be blank")
	}
	if strings.TrimSpace(p.ID) == "" {
		return Invalid(pointer, "Component ID must not be blank")
	}
	b, _ := json.Marshal(p)
	var x any
	_ = json.Unmarshal(b, &x)
	if err := v.CheckSchema("Package", x); err != nil {
		return Invalid(pointer, "Component fields exceed API limits or contain invalid URLs")
	}
	for i, u := range p.RepositoryURLs {
		parsed, err := url.Parse(u)
		if err != nil || !parsed.IsAbs() || strings.IndexFunc(u, unicode.IsSpace) >= 0 {
			return Invalid(fmt.Sprintf("%s/repository_urls/%d", pointer, i), "Expected an absolute URI without whitespace")
		}
	}
	for i, c := range p.ExistingCPEs {
		if !strings.HasPrefix(c, "cpe:2.3:") {
			return Invalid(identifierPointer(pointer, "existing_cpes", i), "Expected CPE 2.3")
		}
		if _, e := naming.UnbindFS(c); e != nil {
			return Invalid(identifierPointer(pointer, "existing_cpes", i), "Invalid CPE 2.3")
		}
	}
	for i, u := range p.ExistingPURLs {
		if _, e := packageurl.FromString(u); e != nil {
			return Invalid(identifierPointer(pointer, "existing_purls", i), "Invalid PURL")
		}
	}
	return nil
}

// ValidateOutput prevents invalid storage responses from leaking through the API.
func (s *Service) ValidateOutput(schema string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var x any
	if err = json.Unmarshal(b, &x); err != nil {
		return err
	}
	return s.validator.CheckSchema(schema, x)
}

func identifierPointer(pointer, field string, index int) string {
	if strings.HasPrefix(pointer, "/input/document/") {
		return pointer
	}
	return fmt.Sprintf("%s/%s/%d", pointer, field, index)
}
