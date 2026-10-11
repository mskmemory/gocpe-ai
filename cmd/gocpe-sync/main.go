// gocpe-sync explicitly runs full-source synchronization. It never starts in API servers.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/mskmemory/gocpe-ai/db"
	"github.com/mskmemory/gocpe-ai/internal/lookup"
	"github.com/mskmemory/gocpe-ai/internal/store/postgres"
	"github.com/mskmemory/gocpe-ai/internal/syncdata"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "synchronization failed:", err)
		os.Exit(1)
	}
}
func run() error {
	source := flag.String("source", "all", "all | nvd | osv")
	stream := flag.String("stream", "all", "NVD: all | cpe | cve | match | history | source")
	archive := flag.String("osv-archive", "osv-all.zip", "local archive path (retained for resume)")
	download := flag.Bool("download-osv", false, "download/replace the official global OSV archive before ingestion")
	migrate := flag.Bool("migrate", false, "apply numbered DB migrations")
	pages := flag.Int("max-pages", 0, "NVD page cap per stream; 0 = all")
	records := flag.Int("max-records", 0, "OSV record cap; 0 = all")
	timeout := flag.Duration("timeout", 48*time.Hour, "overall sync deadline")
	flag.Parse()
	if *source != "all" && *source != "nvd" && *source != "osv" {
		return fmt.Errorf("invalid source")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	pool, e := postgres.OpenPool(ctx, os.Getenv("DATABASE_URL"))
	if e != nil {
		return e
	}
	defer pool.Close()
	if *migrate {
		if e = db.Migrate(ctx, pool); e != nil {
			return e
		}
	}
	repo := postgres.New(pool, postgres.Config{})
	if *source == "all" || *source == "nvd" {
		selected := []string{*stream}
		if *stream == "all" {
			selected = []string{"cpe", "cve", "match", "history", "source"}
		}
		for _, s := range selected {
			fmt.Println("sync nvd", s)
			if e = syncdata.NVD(ctx, repo, syncdata.NVDConfig{APIKey: os.Getenv("NVD_API_KEY"), HTTP: lookup.Config{Timeout: 60 * time.Second, MaxRetries: 3}, MaxPages: *pages}, s); e != nil {
				return e
			}
		}
	}
	if *source == "all" || *source == "osv" {
		if *download {
			fmt.Println("download OSV global archive")
			if e = syncdata.DownloadArchive(ctx, syncdata.OSVArchiveURL, *archive, 0); e != nil {
				return e
			}
		}
		fmt.Println("sync osv all ecosystems")
		return syncdata.OSV(ctx, repo, syncdata.OSVConfig{Archive: *archive, MaxRecords: *records})
	}
	return nil
}
