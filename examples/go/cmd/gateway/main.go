// Command gateway runs the reference GTR gateway.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/sumsub/gtr-gateway/go/gateway"
	"github.com/sumsub/gtr-gateway/go/gtr"
	"github.com/sumsub/gtr-gateway/go/sumsub"

	"gtr-gateway-example/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))

	clientCertificate, err := os.ReadFile(cfg.GTRClientCertPath)
	if err != nil {
		return fmt.Errorf("cannot read GTR_CLIENT_CERT_PATH: %w", err)
	}
	var caCertificate []byte
	if cfg.GTRCACertPath != "" {
		if caCertificate, err = os.ReadFile(cfg.GTRCACertPath); err != nil {
			return fmt.Errorf("cannot read GTR_CA_CERT_PATH: %w", err)
		}
	}
	client, err := gtr.NewClient(gtr.ClientOptions{
		APIURL:                    cfg.GTRAPIURL,
		VASPCode:                  cfg.GTRVASPCode,
		AccessKey:                 cfg.GTRAccessKey,
		SecretKey:                 cfg.GTRSecretKey,
		ClientCertificateP12:      clientCertificate,
		ClientCertificatePassword: cfg.GTRClientCertPassword,
		CACertificatePEM:          caCertificate,
	})
	if err != nil {
		return err
	}
	keyPair, err := gtr.ParseEd25519PrivateKey(cfg.GTRPrivateKey)
	if err != nil {
		return fmt.Errorf("GTR_PRIVATE_KEY: %w", err)
	}

	var sumsubClient sumsub.CallbackAPI
	if cfg.SumsubAppToken != "" {
		sumsubClient, err = sumsub.NewClient(sumsub.ClientOptions{
			APIURL:      cfg.SumsubAPIURL,
			Credentials: sumsub.Credentials{AppToken: cfg.SumsubAppToken, AppSecret: cfg.SumsubAppSecret},
		})
		if err != nil {
			return err
		}
	}
	var decryptor *sumsub.Decryptor
	if cfg.GatewayPGPPrivateKey != "" {
		decryptor, err = sumsub.NewDecryptor(sumsub.DecryptorOptions{
			PrivateKeys:     cfg.GatewayPGPPrivateKey,
			Passphrase:      cfg.GatewayPGPPrivateKeyPassphrase,
			SumsubPublicKey: cfg.SumsubPGPPublicKey,
		})
		if err != nil {
			return err
		}
	}

	handler, err := gateway.NewHandler(gateway.Options{
		GTR:              client,
		Sumsub:           sumsubClient,
		KeyPair:          keyPair,
		SumsubSecretKeys: []string{cfg.SumsubSecretKey, cfg.SumsubSecretKeyPrevious},
		Decryptor:        decryptor,
		Logger:           logger,
	})
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ListenAndServe() }()
	logger.Info("gateway listening", "addr", server.Addr)

	select {
	case err := <-serverErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}
