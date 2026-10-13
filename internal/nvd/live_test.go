package nvd

import (
	"context"
	"github.com/mskmemory/gocpe-ai/internal/lookup"
	"os"
	"testing"
	"time"
)

// Explicit live test: GOCPE_LIVE_EXTERNAL=1 go test ./internal/nvd ./internal/osv -run Live
func TestLiveNVD(t *testing.T) {
	if os.Getenv("GOCPE_LIVE_EXTERNAL") != "1" {
		t.Skip("live external test is opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := New(Config{APIKey: os.Getenv("NVD_API_KEY"), PageSize: 20, MaxPages: 1, HTTP: lookup.Config{Timeout: 20 * time.Second, MaxRetries: 1}})
	result, e := client.Search(ctx, Query{Keyword: "log4j 1.2.17"})
	if e != nil {
		t.Fatal(e)
	}
	if !result.Complete || len(result.Records) == 0 {
		t.Fatalf("empty NVD live response; pages=%d", len(result.Evidence))
	}
}
