package osv

import (
	"context"
	"github.com/mskmemory/gocpe-ai/internal/lookup"
	"os"
	"testing"
	"time"
)

func TestLiveOSV(t *testing.T) {
	if os.Getenv("GOCPE_LIVE_EXTERNAL") != "1" {
		t.Skip("live external test is opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := New(Config{HTTP: lookup.Config{Timeout: 20 * time.Second, MaxRetries: 1}, MaxPages: 1})
	result, e := client.Query(ctx, Query{Package: Package{PURL: "pkg:npm/lodash"}, Version: "4.17.21"})
	if e != nil {
		t.Fatal(e)
	}
	if !result.Complete {
		t.Fatal("OSV pagination incomplete")
	}
}
