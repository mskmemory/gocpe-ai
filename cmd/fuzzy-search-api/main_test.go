package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mskmemory/gocpe-ai/internal/fuzzysearch"
)

func TestFuzzySearchEndpoint(t *testing.T) {
	records := []fuzzysearch.Record{
		{ID: "core", Identifier: "pkg:maven/org.example/log4j-core", Name: "log4j-core", Ecosystem: "Maven"},
		{ID: "api", Identifier: "pkg:maven/org.example/log4j-api", Name: "log4j-api", Ecosystem: "Maven"},
	}
	mux := http.NewServeMux()
	mux.Handle("POST /v1/search/purls", searchHandler("purl", records))
	handler := authenticate("test-token", mux)

	request := httptest.NewRequest(http.MethodPost, "/v1/search/purls", strings.NewReader(`{"query":"log4j-cor","ecosystem":"Maven","limit":5}`))
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"id":"core"`) || !strings.Contains(response.Body.String(), `"edit_distance":1`) {
		t.Fatalf("response did not contain expected fuzzy match: %s", response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/search/purls", strings.NewReader(`{"query":"log4j-core"}`))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}
