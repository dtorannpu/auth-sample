package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/caarlos0/env/v11"
	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

type config struct {
	jwksURL  string   `env:"JWKS_URL,required"`
	issuer   string   `env:"ISSUER,required"`
	audience []string `env:"AUDIENCE,required"`
}

type jwtConfig struct {
	issuer   string   `env:"ISSUER,required"`
	audience []string `env:"AUDIENCE,required"`
	keyFunc  jwt.Keyfunc
}

func initJWKS(ctx context.Context, jwksURL string) (keyfunc.Keyfunc, error) {

	return keyfunc.NewDefaultCtx(ctx, []string{jwksURL})
}

func newJWTMiddleware(cfg jwtConfig) echo.MiddlewareFunc {
	return echojwt.WithConfig(echojwt.Config{
		ParseTokenFunc: func(c *echo.Context, auth string) (interface{}, error) {
			token, err := jwt.Parse(auth, cfg.keyFunc, jwt.WithIssuer(cfg.issuer), jwt.WithAudience(cfg.audience...), jwt.WithExpirationRequired())
			if err != nil {
				c.Logger().Error("failed to parse token", "error", err)
				return nil, echo.ErrUnauthorized
			}
			return token, nil
		},
	})
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := env.ParseAs[config]()
	if err != nil {
		return fmt.Errorf("環境変数の読み込みに失敗しました: %w", err)
	}

	jwks, err := initJWKS(ctx, cfg.jwksURL)
	if err != nil {
		return fmt.Errorf("JWKS初期化失敗: %w", err)
	}

	e := echo.New()
	e.Use(middleware.RequestLogger())
	e.Use(middleware.Recover())

	e.Use(newJWTMiddleware(jwtConfig{
		issuer:   cfg.issuer,
		audience: cfg.audience,
		keyFunc:  jwks.Keyfunc,
	}))

	e.GET("/", func(c *echo.Context) error {
		return c.String(200, "Hello, World!")
	})

	sc := echo.StartConfig{
		Address:         ":1323",
		GracefulTimeout: 5 * time.Second,
	}
	if err := sc.Start(ctx, e); err != nil {
		e.Logger.Error("failed to start server", "error", err)
	}

	return nil
}
