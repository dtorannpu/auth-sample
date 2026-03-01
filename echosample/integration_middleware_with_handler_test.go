package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	echojwt "github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"
)

func TestIntegrationMiddlewareWithHandler(t *testing.T) {
	e := echo.New()
	e.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey: []byte("secret"),
	}))

	e.GET("/", func(c *echo.Context) error {
		return c.String(200, "Hello, World!")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer <TOKEN>")
	res := httptest.NewRecorder()

	e.ServeHTTP(res, req)

	if res.Code != 200 {
		t.Failed()
	}
}
