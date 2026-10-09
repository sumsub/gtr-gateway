// Package config reads the gateway configuration from environment variables.
package config

import (
	"errors"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config holds everything the gateway needs to start.
type Config struct {
	Host     string
	Port     int
	LogLevel slog.Level

	SumsubSecretKey         string
	SumsubSecretKeyPrevious string
	SumsubAPIURL            string
	SumsubAppToken          string
	SumsubAppSecret         string

	GTRAPIURL             string
	GTRVASPCode           string
	GTRAccessKey          string
	GTRSecretKey          string
	GTRClientCertPath     string
	GTRClientCertPassword string
	GTRCACertPath         string
	GTRPrivateKey         string

	GatewayPGPPrivateKey           string
	GatewayPGPPrivateKeyPassphrase string
	SumsubPGPPublicKey             string
}

// Load reads the configuration through getenv (usually os.Getenv) and reports every problem at once.
// Every variable can instead be read from a file: NAME_FILE holds the path, as with Docker and Kubernetes secrets.
func Load(getenv func(string) string) (Config, error) {
	var problems []string
	env := func(name string) string {
		value := getenv(name)
		path := strings.TrimSpace(getenv(name + "_FILE"))
		if path == "" {
			return value
		}
		if value != "" {
			problems = append(problems, name+" and "+name+"_FILE: set only one of them")
			return value
		}
		content, err := os.ReadFile(path)
		if err != nil {
			problems = append(problems, name+"_FILE: "+err.Error())
			return ""
		}
		return strings.TrimRight(string(content), "\r\n")
	}
	required := func(name string) string {
		value := strings.TrimSpace(env(name))
		if value == "" {
			problems = append(problems, name+": required")
		}
		return value
	}
	optional := func(name string) string {
		return strings.TrimSpace(env(name))
	}

	cfg := Config{Host: "0.0.0.0", Port: 8080, LogLevel: slog.LevelInfo}
	if host := optional("HOST"); host != "" {
		cfg.Host = host
	}
	if raw := optional("PORT"); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			problems = append(problems, "PORT: must be a number between 1 and 65535")
		} else {
			cfg.Port = port
		}
	}
	if raw := optional("LOG_LEVEL"); raw != "" {
		if err := cfg.LogLevel.UnmarshalText([]byte(raw)); err != nil {
			problems = append(problems, "LOG_LEVEL: "+err.Error())
		}
	}

	cfg.SumsubSecretKey = required("SUMSUB_SECRET_KEY")
	cfg.SumsubSecretKeyPrevious = optional("SUMSUB_SECRET_KEY_PREVIOUS")
	cfg.SumsubAPIURL = "https://api.sumsub.com"
	if value := optional("SUMSUB_API_URL"); value != "" {
		cfg.SumsubAPIURL = value
	}
	cfg.SumsubAppToken = optional("SUMSUB_APP_TOKEN")
	cfg.SumsubAppSecret = optional("SUMSUB_APP_SECRET")
	if (cfg.SumsubAppToken == "") != (cfg.SumsubAppSecret == "") {
		problems = append(problems, "SUMSUB_APP_TOKEN and SUMSUB_APP_SECRET must be set together")
	}
	cfg.GTRAPIURL = required("GTR_API_URL")
	if cfg.GTRAPIURL != "" {
		if parsed, err := url.Parse(cfg.GTRAPIURL); err != nil || parsed.Scheme == "" || parsed.Host == "" {
			problems = append(problems, "GTR_API_URL: must be an absolute URL")
		}
	}
	cfg.GTRVASPCode = required("GTR_VASP_CODE")
	cfg.GTRAccessKey = required("GTR_ACCESS_KEY")
	cfg.GTRSecretKey = required("GTR_SECRET_KEY")
	cfg.GTRClientCertPath = required("GTR_CLIENT_CERT_PATH")
	cfg.GTRClientCertPassword = env("GTR_CLIENT_CERT_PASSWORD")
	cfg.GTRCACertPath = optional("GTR_CA_CERT_PATH")
	cfg.GTRPrivateKey = required("GTR_PRIVATE_KEY")
	cfg.GatewayPGPPrivateKey = optional("GATEWAY_PGP_PRIVATE_KEY")
	cfg.GatewayPGPPrivateKeyPassphrase = env("GATEWAY_PGP_PRIVATE_KEY_PASSPHRASE")
	cfg.SumsubPGPPublicKey = optional("SUMSUB_PGP_PUBLIC_KEY")
	if (cfg.GatewayPGPPrivateKey == "") != (cfg.SumsubPGPPublicKey == "") {
		problems = append(problems, "GATEWAY_PGP_PRIVATE_KEY and SUMSUB_PGP_PUBLIC_KEY must be set together")
	}

	if len(problems) > 0 {
		return Config{}, errors.New("invalid configuration:\n  " + strings.Join(problems, "\n  "))
	}
	return cfg, nil
}
