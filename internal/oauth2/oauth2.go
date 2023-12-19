package oauth2

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
)

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	E   string `json:"e"`
	N   string `json:"n"`
}
type JWKS struct {
	Keys []JWK `json:"keys"`
}

func ParseJwksFromUri(jwks_uri string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, jwks_uri, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", nil
		}
		return string(data), nil
	} else {
		return "", errors.New("url:" + jwks_uri + " http status code:" + resp.Status)
	}
}

func GetJwksFromIssuer(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", err
	}

	//try /oauth2/jwks for jwks.
	jwks, err := ParseJwksFromUri(u.JoinPath("/oauth2/jwks").String())

	if err != nil {
		log.Printf("WARNING: fail to get jwks from /oauth2/jwks of issuer,trying /.well-known/openid-configuration further. error: %v", err)
	} else {
		return jwks, nil
	}

	//try /.well-known/openid-configuration for jwks_uri
	req, err := http.NewRequest(http.MethodGet, u.JoinPath("/.well-known/openid-configuration").String(), nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		var configmap map[string]interface{}
		err = json.Unmarshal(data, &configmap)
		if err != nil {
			return "", err
		}
		if jwks_uri, ok := configmap["jwks_uri"]; ok {
			return ParseJwksFromUri(jwks_uri.(string))
		} else {
			return "", errors.New("jwks_uri not found in openid-configuration")
		}
	} else {
		return "", errors.New("fail to get /.well-known/openid-configuration from " + issuer)
	}
}
func ParseJWKS(jwksBytes []byte, kid string) (*rsa.PublicKey, error) {
	var jwks JWKS
	err := json.Unmarshal(jwksBytes, &jwks)
	if err != nil {
		return nil, err
	}
	var jwk JWK
	if kid == "" {
		jwk = jwks.Keys[0]
	} else {
		for _, e := range jwks.Keys {
			if e.Kid == kid {
				jwk = e
				break
			}
		}
	}
	if jwk.N == "" {
		return nil, errors.New("no RAS modulus found in jwk")
	}
	// Decode Base64-encoded modulus and exponent
	modulusBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}

	exponentBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	// Parse modulus and exponent as big integers
	modulus := new(big.Int).SetBytes(modulusBytes)
	exponent := new(big.Int).SetBytes(exponentBytes)

	// Create RSA public key
	publicKey := &rsa.PublicKey{
		N: modulus,
		E: int(exponent.Int64()),
	}

	return publicKey, nil
}
