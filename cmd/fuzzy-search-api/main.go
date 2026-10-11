package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"gocpe-ai/internal/fuzzysearch"
)

type searchRequest struct {
	Query     string `json:"query"`
	Vendor    string `json:"vendor,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

type response struct {
	Kind    string               `json:"kind"`
	Query   string               `json:"query"`
	Results []fuzzysearch.Result `json:"results"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP listen address")
	cpeFile := flag.String("cpes", "", "JSON array of CPE dictionary records")
	purlFile := flag.String("purls", "", "JSON array of PURL dictionary records")
	flag.Parse()

	token := os.Getenv("SEARCH_API_TOKEN")
	if token == "" {
		log.Fatal("SEARCH_API_TOKEN is required")
	}
	cpes, err := loadRecords(*cpeFile)
	if err != nil {
		log.Fatalf("load CPE dictionary: %v", err)
	}
	purls, err := loadRecords(*purlFile)
	if err != nil {
		log.Fatalf("load PURL dictionary: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("POST /v1/search/cpes", searchHandler("cpe", cpes))
	mux.Handle("POST /v1/search/purls", searchHandler("purl", purls))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"ok"}`)
	})
	server := &http.Server{Addr: *addr, Handler: authenticate(token, mux), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("fuzzy search API listening on %s (CPE=%d PURL=%d)", *addr, len(cpes), len(purls))
	log.Fatal(server.ListenAndServe())
}

func loadRecords(path string) ([]fuzzysearch.Record, error) {
	if path == "" {
		return []fuzzysearch.Record{}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var records []fuzzysearch.Record
	decoder := json.NewDecoder(io.LimitReader(file, 128<<20))
	if err := decoder.Decode(&records); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("unexpected data after JSON array")
	}
	for i, record := range records {
		if record.ID == "" || record.Name == "" || record.Identifier == "" {
			return nil, fmt.Errorf("record %d requires id, identifier, and name", i)
		}
	}
	return records, nil
}

func searchHandler(kind string, records []fuzzysearch.Record) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var req searchRequest
		if err := decoder.Decode(&req); err != nil || strings.TrimSpace(req.Query) == "" {
			writeError(w, http.StatusBadRequest, "INVALID_QUERY", "query is required and must be valid JSON")
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", "request must contain one JSON object")
			return
		}
		if req.Limit < 0 || req.Limit > 100 {
			writeError(w, http.StatusBadRequest, "INVALID_LIMIT", "limit must be between 1 and 100")
			return
		}
		results := fuzzysearch.Search(records, fuzzysearch.Options{
			Query: req.Query, Vendor: req.Vendor, Ecosystem: req.Ecosystem, Limit: req.Limit,
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response{Kind: kind, Query: req.Query, Results: results})
	})
}

func authenticate(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "valid bearer token required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}
