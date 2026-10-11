// Command migrate applies embedded migrations using DATABASE_URL.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/mskmemory/gocpe-ai/db"
	"github.com/mskmemory/gocpe-ai/internal/store/postgres"
	"os"
	"time"
)

func main() {
	action := flag.String("action", "up", "up, status, or down (destructive)")
	steps := flag.Int("steps", 0, "explicit number of migrations to roll back")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, e := postgres.OpenPool(ctx, os.Getenv("DATABASE_URL"))
	if e != nil {
		fmt.Fprintln(os.Stderr, "database connection failed")
		os.Exit(1)
	}
	defer p.Close()
	switch *action {
	case "up":
		e = db.Migrate(ctx, p)
	case "down":
		e = db.Rollback(ctx, p, *steps)
	case "status":
		var a []db.AppliedMigration
		var pending int
		a, pending, e = db.Status(ctx, p)
		if e == nil {
			for _, v := range a {
				fmt.Printf("%06d %s %s\n", v.Version, v.Name, v.Checksum)
			}
			fmt.Printf("pending: %d\n", pending)
		}
	default:
		e = fmt.Errorf("unknown action")
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
