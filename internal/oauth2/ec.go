package oauth2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
)

// JWK represents a JSON Web Key
type JWK_EC struct {
	Kty string `json:"kty"`
	Use string `json:"sig"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type JWKS_EC struct {
	Keys []JWK_EC `json:"keys"`
}

func GetEccPublicKey(jwksBytes []byte, kid string) (*ecdsa.PublicKey, error) {
	var jwks_ec JWKS_EC
	err := json.Unmarshal([]byte(jwksBytes), &jwks_ec)
	if err != nil {
		return nil, err
	}
	var jwk_ec JWK_EC

	if kid == "" {
		jwk_ec = jwks_ec.Keys[0]
	} else {
		for _, e := range jwks_ec.Keys {
			if e.Kid == kid {
				jwk_ec = e
				break
			}
		}
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk_ec.X)
	if err != nil {
		return nil, err
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk_ec.Y)
	if err != nil {
		return nil, err
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	var curve elliptic.Curve
	if strings.Contains(jwk_ec.Crv, "256") {
		curve = elliptic.P256()
	} else if strings.Contains(jwk_ec.Crv, "384") {
		curve = elliptic.P384()
	} else if strings.Contains(jwk_ec.Crv, "521") {
		curve = elliptic.P521()
	} else if strings.Contains(jwk_ec.Crv, "224") {
		curve = elliptic.P224()
	} else {
		return nil, errors.New("not support crv:" + jwk_ec.Crv)
	}
	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return publicKey, nil
}
