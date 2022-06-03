# oapi-codegen-auth0
Auth0 JWT Request Validator for [deepmap/oapi-codegen](https://github.com/deepmap/oapi-codegen) router middlewares

## Usage

You will need your `AUTH0_DOMAIN` and `AUTH0_AUDIENCE`. By default these will be read from environment variable but
can also optionally be passed in to `NewAuth0Authenticator` with `auth0.WithDomain()` and `auth0.WithAudience()`.

For example with chi, use it as a middleware
```go
func main() {
	mux := chi.NewRouter()

	mux.Use(requestValidator())
	api.HandlerFromMuxWithBaseURL(api.New(), mux, "/api/v1")

	log.Fatal(http.ListenAndServe(":8080", mux))
}

func requestValidator() func(next http.Handler) http.Handler {
	swagger, err := api.GetSwagger()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading openapi spec\n: %s", err)
		os.Exit(1)
	}

	return middleware.OapiRequestValidatorWithOptions(swagger, &middleware.Options{
		Options: openapi3filter.Options{
			AuthenticationFunc: func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
				auth0, err := auth.NewAuth0Authenticator(input.RequestValidationInput.Request, input.Scopes)
				if err != nil {
					return err
				}

				return auth0.Validate()
			},
		},
	})
}
```
