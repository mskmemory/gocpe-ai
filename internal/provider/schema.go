package provider

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/knqyf263/go-cpe/naming"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type object = map[string]any

func str() object { return object{"type": "string", "minLength": 1, "maxLength": 1024} }
func array(item object, max int) object {
	return object{"type": "array", "items": item, "maxItems": max, "uniqueItems": true}
}
func obj(props object, required ...string) object {
	return object{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

var proposalSchema = obj(object{
	"aliases":        array(str(), 5),
	"cpes":           array(obj(object{"value": str(), "reason": str()}, "value", "reason"), 5),
	"purls":          array(obj(object{"value": str(), "reason": str()}, "value", "reason"), 5),
	"missing_fields": array(str(), 10),
}, "aliases", "cpes", "purls", "missing_fields")
var rankingSchema = obj(object{"rankings": array(obj(object{"candidate_id": str(), "evidence_ids": array(str(), 20), "reason": str()}, "candidate_id", "evidence_ids", "reason"), 50)}, "rankings")

// Send the common structural subset; enforce full constraints locally for all vendors.
func wireSchema(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := object{}
		for k, v := range x {
			switch k {
			case "minLength", "maxLength", "maxItems", "uniqueItems":
				continue
			}
			out[k] = wireSchema(v)
		}
		return out
	default:
		return v
	}
}
func validate(raw string, schema object, out any) error {
	value, err := jsonschema.UnmarshalJSON(strings.NewReader(raw))
	if err != nil {
		return failure(InvalidOutput)
	}
	b, _ := json.Marshal(schema)
	resource, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return failure(InvalidOutput)
	}
	compiler := jsonschema.NewCompiler()
	if err = compiler.AddResource("https://gocpe.invalid/output", resource); err != nil {
		return failure(InvalidOutput)
	}
	compiled, err := compiler.Compile("https://gocpe.invalid/output")
	if err != nil {
		return failure(InvalidOutput)
	}
	if compiled.Validate(value) != nil {
		return failure(InvalidOutput)
	}
	if json.Unmarshal([]byte(raw), out) != nil {
		return failure(InvalidOutput)
	}
	return nil
}
func validateProposals(out ProposalResponse, version string) error {
	for _, p := range out.CPEs {
		w, err := naming.UnbindFS(p.Value)
		if err != nil {
			return failure(InvalidOutput)
		}
		v := w.Get("version")
		// Unknown versions must remain logical ANY/NA; concrete versions must match input exactly.
		if s, ok := v.(string); ok && s != version {
			return failure(InvalidOutput)
		}
	}
	for _, p := range out.PURLs {
		u, err := packageurl.FromString(p.Value)
		if err != nil || (u.Version != "" && u.Version != version) {
			return failure(InvalidOutput)
		}
	}
	return nil
}
