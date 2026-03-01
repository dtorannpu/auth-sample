package main

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// テスト用の鍵ペアを生成
func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

const successIssuer = "https://your-issuer.example.com"
const successAudience = "your-audience"

// テスト用のJWTを生成
func generateTestToken(t *testing.T, key *rsa.PrivateKey, opts ...func(*jwt.RegisteredClaims)) string {
	t.Helper()

	claims := jwt.RegisteredClaims{
		Issuer:    successIssuer,
		Audience:  jwt.ClaimStrings{successAudience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	for _, opt := range opts {
		opt(&claims)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func setupTestEcho(key *rsa.PrivateKey, issuer string, audience []string) *echo.Echo {
	e := echo.New()
	e.Use(newJWTMiddleware(jwtConfig{
		issuer:   issuer,
		audience: audience,
		keyFunc: func(token *jwt.Token) (interface{}, error) {
			// テスト用: 固定の公開鍵を使う
			return &key.PublicKey, nil
		},
	}))
	e.GET("/", func(c *echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})
	return e
}

func TestJWTMiddleware(t *testing.T) {
	key := generateTestKey(t)
	issuer := successIssuer
	audience := []string{successAudience}
	e := setupTestEcho(key, issuer, audience)

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{
			name:       "有効なトークン",
			authHeader: "Bearer " + generateTestToken(t, key),
			wantStatus: http.StatusOK,
		},
		{
			name:       "Authorizationヘッダなし",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "不正なトークン",
			authHeader: "Bearer invalid.token.here",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "有効期限切れ",
			authHeader: "Bearer " + generateTestToken(t, key, func(c *jwt.RegisteredClaims) {
				c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Hour))
			}),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "issuerが違う",
			authHeader: "Bearer " + generateTestToken(t, key, func(c *jwt.RegisteredClaims) {
				c.Issuer = "https://wrong-issuer.example.com"
			}),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "audienceが違う",
			authHeader: "Bearer " + generateTestToken(t, key, func(c *jwt.RegisteredClaims) {
				c.Audience = jwt.ClaimStrings{"wrong-audience"}
			}),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "別の鍵で署名",
			authHeader: "Bearer " + func() string {
				otherKey := generateTestKey(t) // 別の鍵
				return generateTestToken(t, otherKey)
			}(),
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()

			e.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}
