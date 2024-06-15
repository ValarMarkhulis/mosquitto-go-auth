package backends

import (
	"context"
	"crypto/tls"
	"fmt"
	h "net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type JWKremoteJWTChecker struct {
	jwkUrI        string
	superuserUri  string
	aclUri        string
	userAgent     string
	host          string
	port          string
	hostWhitelist []string
	withTLS       bool
	verifyPeer    bool
	paramsMode    string
	httpMethod    string
	responseMode  string
	timeout       int
	audience      string

	options tokenOptions

	client *h.Client
}

type JWKResponse struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

func NewJWKRemoteJWTChecker(authOpts map[string]string, options tokenOptions, version string) (jwtChecker, error) {
	var checker = &JWKremoteJWTChecker{
		withTLS:      false,
		verifyPeer:   false,
		responseMode: "status",
		paramsMode:   "json",
		httpMethod:   h.MethodPost,
		options:      options,
	}

	missingOpts := ""
	remoteJWKOk := true

	if responseMode, ok := authOpts["jwt_response_mode"]; ok {
		if responseMode == "text" || responseMode == "json" {
			checker.responseMode = responseMode
		}
	}

	if paramsMode, ok := authOpts["jwt_params_mode"]; ok {
		if paramsMode == "form" {
			checker.paramsMode = paramsMode
		}
	}

	if httpMethod, ok := authOpts["jwt_http_method"]; ok {
		switch httpMethod {
		case h.MethodGet, h.MethodPut:
			checker.httpMethod = httpMethod
		}
	}

	if userUri, ok := authOpts["jwt_jwk_uri"]; ok {
		checker.jwkUrI = userUri
	} else {
		remoteJWKOk = false
		missingOpts += " jwt_jwk_uri"
	}

	if audience, ok := authOpts["jwt_jwk_audience"]; ok {
		checker.audience = audience
	} else {
		remoteJWKOk = false
		missingOpts += " jwt_jwk_audience"
	}

	checker.userAgent = fmt.Sprintf("%s-%s", defaultUserAgent, version)
	if userAgent, ok := authOpts["jwt_user_agent"]; ok {
		checker.userAgent = userAgent
	}

	if hostname, ok := authOpts["jwt_host"]; ok {
		checker.host = hostname
	} else if options.parseToken {
		checker.host = ""
	} else {
		remoteJWKOk = false
		missingOpts += " jwt_host"
	}

	if hostWhitelist, ok := authOpts["jwt_host_whitelist"]; ok {
		if hostWhitelist == whitelistMagicForAnyHost {
			log.Warning(
				"Backend host whitelisting is turned off. This is not secure and should not be used in " +
					"the production environment")
			checker.hostWhitelist = append(checker.hostWhitelist, whitelistMagicForAnyHost)
		} else {
			for _, host := range strings.Split(hostWhitelist, ",") {
				strippedHost := strings.TrimSpace(host)
				/* Not-so-strict check if we have a valid value (domain name or ip address with optional
				port) as a part of the host whitelist. TODO: Consider using more robust check, i.e.
				using "govalidator" or similar package instead. */
				if matched, _ := regexp.MatchString(`^[a-zA-Z0-9][a-zA-Z0-9-\.]+[a-zA-Z0-9](?:\:[0-9]+)?$`, strippedHost); !matched {
					return nil, errors.Errorf("JWT backend error: bad host %s in jwt_host_whitelist", strippedHost)
				}
				checker.hostWhitelist = append(checker.hostWhitelist, strippedHost)
			}
		}
	} else if checker.host == "" {
		remoteJWKOk = false
		missingOpts += " jwt_host_whitelist"
	}

	/* 	if port, ok := authOpts["jwt_port"]; ok {
	   		checker.port = port
	   	} else {
	   		remoteJWKOk = false
	   		missingOpts += " jwt_port"
	   	} */

	if withTLS, ok := authOpts["jwt_with_tls"]; ok && withTLS == "true" {
		checker.withTLS = true
	}

	if verifyPeer, ok := authOpts["jwt_verify_peer"]; ok && verifyPeer == "true" {
		checker.verifyPeer = true
	}

	if !remoteJWKOk {
		return nil, errors.Errorf("JWT backend error: missing remote jwk options: %s", missingOpts)
	}

	checker.timeout = 5
	if timeoutString, ok := authOpts["jwt_http_timeout"]; ok {
		if timeout, err := strconv.Atoi(timeoutString); err == nil {
			checker.timeout = timeout
		} else {
			log.Errorf("unable to parse timeout: %s", err)
		}
	}

	checker.client = &h.Client{Timeout: time.Duration(checker.timeout) * time.Second}

	if !checker.verifyPeer {
		tr := &h.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		checker.client.Transport = tr
	}

	return checker, nil
}

func (o *JWKremoteJWTChecker) GetUser(token string) (bool, error) {
	var dataMap map[string]interface{}
	var urlValues url.Values

	if o.options.parseToken {
		_, err := getUsernameForToken(o.options, token, o.options.skipUserExpiration)

		if err != nil {
			log.Printf("jwt remote get user error: %s", err)
			return false, err
		}

	}

	return o.jwkRequest(o.jwkUrI, o.audience, token, dataMap, urlValues)
}

func (o *JWKremoteJWTChecker) GetSuperuser(token string) (bool, error) {
	// Not implemented
	return false, nil
}

func (o *JWKremoteJWTChecker) CheckAcl(token, topic, clientid string, acc int32) (bool, error) {
	// Not implemented
	return false, nil
}

func (o *JWKremoteJWTChecker) Halt() {
	// NO-OP
}

func (o *JWKremoteJWTChecker) jwkRequest(uri, audience string, token string, dataMap map[string]interface{}, urlValues url.Values) (bool, error) {

	validator, err := EnsureValidToken(uri, audience)

	if err != nil {
		log.Fatalf("Failed to set up the jwt validator")
		return false, err
	}

	resp, err := validator.ValidateToken(context.Background(), token)
	if err != nil {
		log.Fatalf("Failed to validate the token: %v", err)
		return false, err
	}

	log.Println(resp)
	log.Debugf("jwt request approved for %s", token)
	return true, nil
}

func (o *JWKremoteJWTChecker) getHost(token string) (string, error) {
	if o.host != "" {
		return o.host, nil
	}

	// Actually this should never happen because of configuration sanity check. TODO: consider removing this condition.
	if !o.options.parseToken {
		errorString := "impossible to obtain host for the authorization request - token parsing is turned off"
		return "", errors.New(errorString)
	}

	iss, err := getIssForToken(o.options, token, o.options.skipUserExpiration)
	if err != nil {
		errorString := fmt.Sprintf("cannot obtain host for the authorization request from token %s: %s", token, err)
		return "", errors.New(errorString)
	}

	if !o.isHostWhitelisted(iss) {
		errorString := fmt.Sprintf("host %s obtained from host is not whitelisted; rejecting", iss)
		return "", errors.New(errorString)
	}

	return iss, nil
}

func (o *JWKremoteJWTChecker) isHostWhitelisted(host string) bool {
	if len(o.hostWhitelist) == 1 && o.hostWhitelist[0] == whitelistMagicForAnyHost {
		return true
	}

	for _, whitelistedHost := range o.hostWhitelist {
		if whitelistedHost == host {
			return true
		}
	}
	return false
}



// EnsureValidToken will check the validity of our JWT.
func EnsureValidToken(uri string, audience string) (*validator.Validator, error) {
	issuerURL, err := url.Parse(uri)
	if err != nil {
		log.Fatalf("Failed to parse the issuer url: %v", err)
	}

	provider := jwks.NewCachingProvider(issuerURL, 5*time.Minute)

	jwtValidator, err := validator.New(
		provider.KeyFunc,
		validator.RS256,
		issuerURL.String(),
		[]string{audience},
		validator.WithAllowedClockSkew(time.Minute),
	)
	if err != nil {
		log.Fatalf("Failed to set up the jwt validator")
	}

	return jwtValidator, err
}
