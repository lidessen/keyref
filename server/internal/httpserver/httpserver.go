// Package httpserver wires the API handler into a running HTTP server:
// ACME-managed TLS on 443/80 when KEYREF_DOMAIN is set, plain HTTP on
// the listen address otherwise (development and e2e mode, design
// §10.4). It also runs the background maintenance loops: the rolling
// 90-day change-log cleanup (design §10.6) and expired-session pruning.
package httpserver

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/lidessen/keyref/server/internal/store"
)

// Options configures one server run.
type Options struct {
	DataDir     string
	Domain      string // KEYREF_DOMAIN: enables ACME
	ACMEEmail   string // KEYREF_ACME_EMAIL
	ListenAddr  string // plain-HTTP listen address (no domain set)
	TLSAddr     string // defaults to ":443"
	HTTPAddr    string // ACME http-01 + redirect; defaults to ":80"
	CleanupTick time.Duration
}

// Maintenance intervals.
const (
	defaultCleanupTick = time.Hour
	changeLogRetention = 90 * 24 * time.Hour // design §10.6
)

// Run blocks serving until SIGINT/SIGTERM.
func Run(handler http.Handler, st *store.Store, opt Options) error {
	if opt.CleanupTick <= 0 {
		opt.CleanupTick = defaultCleanupTick
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		ticker := time.NewTicker(opt.CleanupTick)
		defer ticker.Stop()
		cleanup(ctx, st) // run once at startup too
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanup(ctx, st)
			}
		}
	}()

	errCh := make(chan error, 2)
	var servers []*http.Server

	if opt.Domain != "" {
		certDir := filepath.Join(opt.DataDir, "acme-certs")
		if err := os.MkdirAll(certDir, 0o700); err != nil {
			return err
		}
		manager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(opt.Domain),
			Cache:      autocert.DirCache(certDir),
			Email:      opt.ACMEEmail,
		}
		if opt.HTTPAddr == "" {
			opt.HTTPAddr = ":80"
		}
		if opt.TLSAddr == "" {
			opt.TLSAddr = ":443"
		}
		httpSrv := &http.Server{
			Addr:              opt.HTTPAddr,
			Handler:           manager.HTTPHandler(nil),
			ReadHeaderTimeout: 10 * time.Second,
		}
		tlsSrv := &http.Server{
			Addr:              opt.TLSAddr,
			Handler:           handler,
			TLSConfig:         &tls.Config{GetCertificate: manager.GetCertificate, MinVersion: tls.VersionTLS12},
			ReadHeaderTimeout: 10 * time.Second,
		}
		servers = append(servers, httpSrv, tlsSrv)
		go func() { errCh <- httpSrv.ListenAndServe() }()
		go func() { errCh <- tlsSrv.ListenAndServeTLS("", "") }()
		log.Printf("httpserver: serving https on %s (domain %s, ACME cache %s)", opt.TLSAddr, opt.Domain, certDir)
	} else {
		listen := opt.ListenAddr
		if listen == "" {
			listen = "127.0.0.1:8080"
		}
		srv := &http.Server{
			Addr:              listen,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		servers = append(servers, srv)
		ln, err := net.Listen("tcp", listen)
		if err != nil {
			return err
		}
		go func() { errCh <- srv.Serve(ln) }()
		log.Printf("httpserver: serving plain http on %s (development mode; set KEYREF_DOMAIN for ACME/TLS)", listen)
	}

	select {
	case <-ctx.Done():
		log.Print("httpserver: shutting down")
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			shutdown(servers)
			return err
		}
	}
	shutdown(servers)
	<-cleanupDone
	return nil
}

func shutdown(servers []*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		srv.Shutdown(ctx)
	}
}

// cleanup runs the rolling change-log retention (design §10.6).
func cleanup(ctx context.Context, st *store.Store) {
	before := time.Now().Add(-changeLogRetention).UnixMilli()
	if err := st.DeleteChangesOlderThan(ctx, before); err != nil {
		log.Printf("httpserver: change-log cleanup: %v", err)
	}
	if err := st.DeleteExpiredPairSessions(ctx, time.Now().Add(-time.Hour).UnixMilli()); err != nil {
		log.Printf("httpserver: pair-session cleanup: %v", err)
	}
}
