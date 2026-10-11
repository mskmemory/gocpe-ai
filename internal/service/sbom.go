package service

import (
	"encoding/json"
	"fmt"
	"github.com/knqyf263/go-cpe/naming"
	"strings"
)

func text(m map[string]any, k string) string { v, _ := m[k].(string); return v }
func object(v any) map[string]any            { m, _ := v.(map[string]any); return m }
func list(v any) []any                       { a, _ := v.([]any); return a }
func (v *Validator) parseSBOM(format string, doc map[string]any) ([]Component, error) {
	version := "spdx"
	if format == "cyclonedx" {
		version = text(doc, "specVersion")
		if text(doc, "bomFormat") != "CycloneDX" || (version != "1.5" && version != "1.6") {
			return nil, Invalid("/input/document/specVersion", "Supported CycloneDX versions are 1.5 and 1.6")
		}
	}
	if format == "spdx" && text(doc, "spdxVersion") != "SPDX-2.3" {
		return nil, Invalid("/input/document/spdxVersion", "Supported SPDX version is 2.3")
	}
	if err := v.sbom[version].Validate(doc); err != nil {
		return nil, Invalid("/input/document", "Does not match the supported SBOM schema")
	}
	out := []Component{}
	base := "/input/document"
	add := func(p Package, pointer string, raw any) error {
		if len(out) >= MaxComponents {
			return Invalid(base, "SBOM exceeds 1000 components")
		}
		if p.ID == "" {
			p.ID = "generated-" + digest([]byte(pointer))
		}
		b, _ := json.Marshal(raw)
		out = append(out, Component{Package: p, SourcePointer: pointer, RawValues: b})
		return nil
	}
	if format == "cyclonedx" {
		var walk func(map[string]any, string) error
		walk = func(c map[string]any, pointer string) error {
			p := Package{ID: text(c, "bom-ref"), Name: text(c, "name"), Version: text(c, "version"), Namespace: text(c, "group")}
			p.Vendor = text(object(c["manufacturer"]), "name")
			if p.Vendor == "" {
				p.Vendor = text(object(c["supplier"]), "name")
			}
			if u := text(c, "purl"); u != "" {
				p.ExistingPURLs = []string{u}
			}
			if cp := text(c, "cpe"); cp != "" {
				p.ExistingCPEs = []string{cp}
			}
			for _, x := range list(c["externalReferences"]) {
				r := object(x)
				if text(r, "type") == "vcs" {
					p.RepositoryURLs = append(p.RepositoryURLs, text(r, "url"))
				}
			}
			if err := add(p, pointer, c); err != nil {
				return err
			}
			for i, x := range list(c["components"]) {
				if err := walk(object(x), fmt.Sprintf("%s/components/%d", pointer, i)); err != nil {
					return err
				}
			}
			return nil
		}
		if c := object(object(doc["metadata"])["component"]); c != nil {
			if err := walk(c, base+"/metadata/component"); err != nil {
				return nil, err
			}
		}
		for i, x := range list(doc["components"]) {
			if err := walk(object(x), fmt.Sprintf("%s/components/%d", base, i)); err != nil {
				return nil, err
			}
		}
	} else {
		for i, x := range list(doc["packages"]) {
			c := object(x)
			pointer := fmt.Sprintf("%s/packages/%d", base, i)
			vendor := text(c, "originator")
			if vendor == "" || vendor == "NOASSERTION" {
				vendor = text(c, "supplier")
			}
			if vendor == "NOASSERTION" {
				vendor = ""
			}
			vendor = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(vendor, "Organization:"), "Person:"))
			p := Package{ID: text(c, "SPDXID"), Name: text(c, "name"), Version: text(c, "versionInfo"), Vendor: vendor}
			for _, x := range list(c["externalRefs"]) {
				r := object(x)
				t, u := text(r, "referenceType"), text(r, "referenceLocator")
				switch t {
				case "purl":
					p.ExistingPURLs = append(p.ExistingPURLs, u)
				case "cpe23Type":
					p.ExistingCPEs = append(p.ExistingCPEs, u)
				case "cpe22Type":
					w, e := naming.UnbindURI(u)
					if e != nil {
						return nil, Invalid(pointer+"/externalRefs", "Invalid CPE URI")
					}
					p.ExistingCPEs = append(p.ExistingCPEs, naming.BindToFS(w))
				}
			}
			if err := add(p, pointer, c); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}
