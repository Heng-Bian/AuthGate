package oauth2

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
)

// JWK represents a JSON Web Key
type JWK_OKP struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

type JWKS_OKP struct {
	Keys []JWK_OKP `json:"keys"`
}

func GetOKPPublicKey(jwksBytes []byte, kid string) (interface{}, error) {
	var jwks_okp JWKS_OKP
	err := json.Unmarshal([]byte(jwksBytes), &jwks_okp)
	if err != nil {
		return nil, err
	}
	var jwk_okp JWK_OKP

	if kid == "" {
		jwk_okp = jwks_okp.Keys[0]
	} else {
		for _, e := range jwks_okp.Keys {
			if e.Kid == kid {
				jwk_okp = e
				break
			}
		}
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk_okp.X)
	if err != nil {
		return nil, err
	}

	return ed25519.PublicKey(xBytes), nil
}
