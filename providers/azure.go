package providers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/bitly/oauth2_proxy/api"

	"golang.org/x/oauth2"

	oidc "github.com/coreos/go-oidc"
)

type AzureProvider struct {
	*ProviderData
	Tenant string
}

func NewAzureProvider(p *ProviderData) *AzureProvider {
	p.ProviderName = "Azure"

	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme:   "https",
			Host:     "graph.windows.net",
			Path:     "/me",
			RawQuery: "api-version=1.6",
		}
	}
	if p.ProtectedResource == nil || p.ProtectedResource.String() == "" {
		p.ProtectedResource = &url.URL{
			Scheme: "https",
			Host:   "graph.windows.net",
		}
	}
	if p.Scope == "" {
		p.Scope = "openid"
	}

	return &AzureProvider{ProviderData: p}
}

func (p *AzureProvider) Configure(tenant string) {
	p.Tenant = tenant
	if tenant == "" {
		p.Tenant = "common"
	}

	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + p.Tenant + "/oauth2/authorize"}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + p.Tenant + "/oauth2/token",
		}
	}
}

func getAzureHeader(access_token string) http.Header {
	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", access_token))
	return header
}

func getEmailFromJSON(json *simplejson.Json) (string, error) {
	var email string
	var err error

	email, err = json.Get("mail").String()

	if err != nil || email == "" {
		otherMails, otherMailsErr := json.Get("otherMails").Array()
		if len(otherMails) > 0 {
			email = otherMails[0].(string)
		}
		err = otherMailsErr
	}

	return email, err
}

func (p *AzureProvider) GetEmailAddress(s *SessionState) (string, error) {
	var email string
	var err error

	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getAzureHeader(s.AccessToken)

	json, err := api.Request(req)

	if err != nil {
		return "", err
	}

	email, err = getEmailFromJSON(json)

	if err == nil && email != "" {
		return email, err
	}

	email, err = json.Get("userPrincipalName").String()

	if err != nil {
		log.Printf("failed making request %s", err)
		return "", err
	}

	if email == "" {
		log.Printf("failed to get email address")
		return "", err
	}

	return email, err
}

func GetScopes(providerScope string, openidScope string) []string {
	if providerScope != openidScope {
		scopes := []string{oidc.ScopeOpenID, "profile", "email", "groups", providerScope}
		return scopes
	} else {
		scopes := []string{oidc.ScopeOpenID, "profile", "email", "groups"}
		return scopes
	}
}

func (p *AzureProvider) ValidateBearerToken(redirectURL string, token string) (s *SessionState, err error) {
	ctx := context.Background()
	// provider, err := oidc.NewProvider(ctx, "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47")
	// provider, err := oidc.NewProvider(ctx, "https://sts.windows.net/9188040d-6c67-4c5b-b112-36a304b66dad/")
	var issuer = fmt.Sprintf("https://sts.windows.net/%s/", p.Tenant)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		// handle error
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	scopes := GetScopes(p.Scope, oidc.ScopeOpenID)

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,

		//Endpoint: oauth2.Endpoint{
		//	//TokenURL: p.RedeemURL.String(),
		//	AuthURL:  "https://login.microsoftonline.com/common/oauth2/authorize",
		//	TokenURL: "https://login.microsoftonline.com/common/oauth2/token",
		//},

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		RedirectURL: redirectURL,

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: scopes,
	}

	var verifier = provider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})

	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	// Extract custom claims.
	var claims struct {
		Email          string `json:"email"`
		Email_Verified *bool  `json:"email_verified"`
		TenantID       string `json:"tid"`
		Name           string `json:"name"`
		Upn            string `json:"upn"`
		Exp            int64  `json:"exp"`
		AppID          string `json:"appid"`
	}

	if err := idToken.Claims(&claims); err != nil {
		// return nil, fmt.Errorf("failed to parse id_token claims: %v", err)

	}

	if claims.Email == "" {
		// some UPNs don't have an email configured. Use UPN instead.

		if claims.Upn != "" {
			claims.Email = claims.Upn
		} else {
			// Token may be for an App Registration.  Use App ID as "user"
			// See: https://blogs.msdn.microsoft.com/aaddevsup/2018/04/12/implementing-service-to-service-authorization-and-getting-the-access-token-with-postman-utilizing-client-credential-grant-type/
			claims.Email = claims.AppID
			claims.Name = claims.AppID
		}
	}

	if claims.Email == "" {
		return nil, fmt.Errorf("id_token did not contain an email, upn, or appid")
	}
	if claims.Email_Verified != nil && !*claims.Email_Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
	}

	s = &SessionState{
		Email:       claims.Email,
		User:        claims.Name,
		IdToken:     idToken.AccessTokenHash,
		ExpiresOn:   time.Unix(claims.Exp, 0),
		AccessToken: token,
	}

	return

}
