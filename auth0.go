package auth0

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
)

type Auth0 struct {
	Domain   string
	Audience string
}

type Options func(*Auth0)

func WithDomain(domain string) Options {
	return func(o *Auth0) {
		o.Domain = domain
	}
}

func WithAudience(audience string) Options {
	return func(o *Auth0) {
		o.Audience = audience
	}
}

// CustomClaims contains custom data we want from the token.
type CustomClaims struct {
	Scopes string `json:"scope"`
}

// Validate does nothing here, but we need
// it to satisfy validator.CustomClaims interface.
func (c CustomClaims) Validate(ctx context.Context) error {
	return nil
}

// HasScope checks whether our claims have a specific scope.
func (c CustomClaims) HasScope(expectedScope string) bool {
	result := strings.Split(c.Scopes, " ")
	for i := range result {
		if result[i] == expectedScope {
			return true
		}
	}

	return false
}

type Auth0Authenticator struct {
	Request       *http.Request
	AllowedScopes []string
	Validator     func(ctx context.Context, tokenString string) (interface{}, error)
}

func NewAuth0Authenticator(r *http.Request, allowedScopes []string, opts ...Options) (*Auth0Authenticator, error) {
	auth0 := &Auth0{
		Domain:   os.Getenv("AUTH0_DOMAIN"),
		Audience: os.Getenv("AUTH0_AUDIENCE"),
	}

	for _, opt := range opts {
		opt(auth0)
	}

	issueURL, err := url.Parse("https://" + auth0.Domain + "/")
	if err != nil {
		return nil, fmt.Errorf("failed to parse the issuer url: %v", err)
	}

	provider := jwks.NewCachingProvider(issueURL, 5*time.Minute)

	jwtValidator, err := validator.New(
		provider.KeyFunc,
		validator.RS256,
		issueURL.String(),
		[]string{auth0.Audience},
		validator.WithCustomClaims(
			func() validator.CustomClaims {
				return &CustomClaims{}
			},
		),
		validator.WithAllowedClockSkew(time.Minute),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to set up the jwt validator: %v", err)
	}

	return &Auth0Authenticator{
		Request:       r,
		AllowedScopes: allowedScopes,
		Validator:     jwtValidator.ValidateToken,
	}, nil
}

func (a *Auth0Authenticator) Validate() error {
	r := a.Request

	token, err := jwtmiddleware.AuthHeaderTokenExtractor(r)
	if err != nil {
		return fmt.Errorf("error extracing token: %w", err)
	}

	if token == "" {
		return errors.New("jwt missing")
	}

	validToken, err := a.Validator(r.Context(), token)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	*r = *r.Clone(
		context.WithValue(r.Context(), jwtmiddleware.ContextKey{}, validToken),
	)

	// Validate Scopes
	claims := validToken.(*validator.ValidatedClaims).CustomClaims.(*CustomClaims)
	if !claims.HasScope(a.AllowedScopes[0]) {
		return fmt.Errorf("invalid scope: %s", claims.Scopes)
	}

	return nil
}
