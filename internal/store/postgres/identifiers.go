package postgres

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	packageurl "github.com/package-url/packageurl-go"

	"github.com/mskmemory/gocpe-ai/internal/store"
)

// purlNormalizationVersion identifies the canonicalization rules stored in
// purls.normalization_version. Changing the parser version or rules requires
// a data migration (see docs/database-design.md).
const purlNormalizationVersion = "packageurl-go@v0.1.3+pypi-pep503"

type parsedCPE struct {
	part, vendor, product, version string
	attributes                     map[string]string
}

var cpeExtraAttributes = []string{
	common.AttributeUpdate, common.AttributeEdition, common.AttributeLanguage,
	common.AttributeSwEdition, common.AttributeTargetSw, common.AttributeTargetHw,
	common.AttributeOther,
}

// parseCPE unbinds a CPE 2.3 formatted string with an escape-aware parser and
// returns each attribute in formatted-string form: ANY => "*", NA => "-",
// literal values keep their FS escaping (e.g. `foo\:bar`).
func parseCPE(name string) (parsedCPE, error) {
	wfn, err := naming.UnbindFS(name)
	if err != nil {
		return parsedCPE{}, fmt.Errorf("%w: CPE 2.3 formatted string rejected by parser", store.ErrInvalid)
	}
	p := parsedCPE{
		part:       fsValue(wfn.Get(common.AttributePart)),
		vendor:     fsValue(wfn.Get(common.AttributeVendor)),
		product:    fsValue(wfn.Get(common.AttributeProduct)),
		version:    fsValue(wfn.Get(common.AttributeVersion)),
		attributes: make(map[string]string, len(cpeExtraAttributes)),
	}
	for _, a := range cpeExtraAttributes {
		p.attributes[a] = fsValue(wfn.Get(a))
	}
	return p, nil
}

// fsValue implements bind_value_for_fs from NISTIR 7695 §6.2.2.2/6.2.2.3:
// logical values bind to "*"/"-"; in strings the quoting of '.', '-' and '_'
// is removed and every other quoted character keeps its backslash.
func fsValue(v any) string {
	if lv, ok := v.(common.LogicalValue); ok {
		if lv.IsANY() {
			return "*"
		}
		if lv.IsNA() {
			return "-"
		}
	}
	s, ok := v.(string)
	if !ok {
		return "*" // unset attribute in a WFN means ANY
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			n := s[i+1]
			if n == '.' || n == '-' || n == '_' {
				b.WriteByte(n)
			} else {
				b.WriteByte('\\')
				b.WriteByte(n)
			}
			i++
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

type parsedPURL struct {
	canonical  string
	purl       packageurl.PackageURL
	qualifiers map[string]string
}

// canonicalPURL parses and normalizes a PURL (type-specific rules, sorted
// qualifiers) and returns the canonical string including version,
// qualifiers and subpath.
func canonicalPURL(raw string) (parsedPURL, error) {
	p, err := packageurl.FromString(strings.TrimSpace(raw))
	if err != nil {
		return parsedPURL{}, fmt.Errorf("%w: PURL rejected by parser", store.ErrInvalid)
	}
	if p.Type == "pypi" {
		p.Name = regexp.MustCompile(`[-_.]+`).ReplaceAllString(strings.ToLower(p.Name), "-")
	}
	sort.SliceStable(p.Qualifiers, func(i, j int) bool { return p.Qualifiers[i].Key < p.Qualifiers[j].Key })
	q := p.Qualifiers.Map()
	if q == nil {
		q = map[string]string{}
	}
	return parsedPURL{canonical: p.ToString(), purl: p, qualifiers: q}, nil
}
