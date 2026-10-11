package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mskmemory/gocpe-ai/internal/httpapi"
	"github.com/mskmemory/gocpe-ai/internal/service"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	flag.Parse()
	var configured map[string]string
	if err := json.Unmarshal([]byte(os.Getenv("GOCPE_API_TOKENS")), &configured); err != nil {
		return errors.New("GOCPE_API_TOKENS must be a JSON map of token to owner ID")
	}
	tokens := map[string]httpapi.Principal{}
	for token, owner := range configured {
		tokens[token] = httpapi.Principal{OwnerID: owner, Read: true, Write: true}
	}
	auth, err := httpapi.NewStaticAuth(tokens)
	if err != nil {
		return err
	}
	svc, err := service.New(service.Config{Store: service.UnavailableStore{}, CursorKey: []byte(os.Getenv("GOCPE_CURSOR_KEY"))})
	if err != nil {
		return err
	}
	handler, err := httpapi.New(svc, auth)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	log.Print("API foundation started; database and resolution worker are not configured")
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}
