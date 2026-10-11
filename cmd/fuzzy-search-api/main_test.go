package main

import (
	"encoding/json"
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
	assertErrorRequestID(t, response)
}

func TestFuzzySearchValidatesQueryAndLimit(t *testing.T) {
	handler := searchHandler("purl", []fuzzysearch.Record{{ID: "one", Identifier: "pkg:maven/example/core", Name: "core"}})
	tests := []struct {
		name string
		body string
	}{
		{name: "query too long", body: `{"query":"` + strings.Repeat("a", 513) + `"}`},
		{name: "explicit zero limit", body: `{"query":"core","limit":0}`},
		{name: "negative limit", body: `{"query":"core","limit":-1}`},
		{name: "limit over maximum", body: `{"query":"core","limit":101}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/search/purls", strings.NewReader(tt.body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
			}
			assertErrorRequestID(t, response)
		})
	}
}

func assertErrorRequestID(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	var payload struct {
		Error struct {
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if payload.Error.RequestID == "" {
		t.Fatal("error response is missing error.request_id")
	}
}
