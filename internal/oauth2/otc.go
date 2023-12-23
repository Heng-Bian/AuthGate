package oauth2

import (
	"encoding/base64"
	"encoding/json"
)

// JWK represents a JSON Web Key
type JWK_OTC struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	K   string `json:"k"`
}

type JWKS_OTC struct {
	Keys []JWK_OTC `json:"keys"`
}

func GetOTCPublicKey(jwksBytes []byte, kid string) (interface{}, error) {
	var jwks_otc JWKS_OTC
	err := json.Unmarshal([]byte(jwksBytes), &jwks_otc)
	if err != nil {
		return nil, err
	}
	var jwk_otc JWK_OTC

	if kid == "" {
		jwk_otc = jwks_otc.Keys[0]
	} else {
		for _, e := range jwks_otc.Keys {
			if e.Kid == kid {
				jwk_otc = e
				break
			}
		}
	}

	kBytes, err := base64.RawURLEncoding.DecodeString(jwk_otc.K)
	if err != nil {
		return nil, err
	}

	return kBytes, nil
}
