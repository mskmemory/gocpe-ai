// Package api embeds the HTTP contract and offline SBOM schemas.
package api

import (
	"context"
	"embed"
	"github.com/getkin/kin-openapi/openapi3"
)

//go:embed openapi.json schemas/*
var Files embed.FS

func Load() (*openapi3.T, error) {
	b, err := Files.ReadFile("openapi.json")
	if err != nil {
		return nil, err
	}
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(b)
	if err != nil {
		return nil, err
	}
	if err = doc.Validate(context.Background()); err != nil {
		return nil, err
	}
	return doc, nil
}
