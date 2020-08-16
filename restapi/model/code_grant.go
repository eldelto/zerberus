package model

type CodeGrantAuthorization struct {
	ClientID string
	RedirectURI string
	Scope []string
	State string
	Code string
}