package fuzzysearch

import "testing"

func TestSearchRanksExactAndTypo(t *testing.T) {
	records := []Record{
		{ID: "b", Identifier: "pkg:maven/org.example/log4j-core", Name: "log4j-core", Ecosystem: "Maven"},
		{ID: "a", Identifier: "pkg:maven/org.example/log4j-api", Name: "log4j-api", Ecosystem: "Maven"},
		{ID: "c", Identifier: "pkg:npm/log4j", Name: "log4j", Ecosystem: "npm"},
	}
	got := Search(records, Options{Query: " LOG4J-CORE ", Limit: 10})
	if len(got) != 3 || got[0].ID != "b" || got[0].EditDistance != 0 {
		t.Fatalf("unexpected ranking: %#v", got)
	}
	got = Search(records, Options{Query: "log4j-cor", Limit: 10})
	if len(got) != 3 || got[0].ID != "b" || got[0].EditDistance != 1 {
		t.Fatalf("expected typo to rank nearest name first: %#v", got)
	}
}

func TestSearchFiltersAndCaps(t *testing.T) {
	records := []Record{
		{ID: "1", Name: "alpha", Vendor: "Acme", Ecosystem: "npm"},
		{ID: "2", Name: "alpha", Vendor: "Other", Ecosystem: "npm"},
		{ID: "3", Name: "alpha", Vendor: "Acme", Ecosystem: "maven"},
	}
	got := Search(records, Options{Query: "alpha", Vendor: "ACME", Ecosystem: "npm", Limit: 1000})
	if len(got) != 1 || got[0].ID != "1" {
		t.Fatalf("unexpected filtered results: %#v", got)
	}
	got = Search(records, Options{Query: "alpha", Limit: 1})
	if len(got) != 1 {
		t.Fatalf("limit not applied: %#v", got)
	}
}

func TestSearchUnicodeCase(t *testing.T) {
	records := []Record{{ID: "1", Name: "製品Alpha"}}
	got := Search(records, Options{Query: "製品ALPHA"})
	if len(got) != 1 || got[0].EditDistance != 0 {
		t.Fatalf("expected case-insensitive search to match: %#v", got)
	}
}
