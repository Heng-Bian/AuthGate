package oauth2

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"time"
)

var pubkey *rsa.PublicKey
var lastModified = time.Now().Unix()

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



func GetRsaPublicKey(jwksBytes []byte, kid string) (*rsa.PublicKey, error) {
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

func GetPublicKeyFromIssuer0(issuer string, kid string) (*rsa.PublicKey, error) {
	if pubkey != nil && time.Now().Unix()-lastModified < 300 {
		return pubkey, nil
	}
	jwks, err := GetJwksFromIssuer(issuer)
	if err != nil {
		return nil, err
	}
	key, err := GetRsaPublicKey([]byte(jwks), kid)
	if err != nil {
		return nil, err
	}
	pubkey = key
	lastModified = time.Now().Unix()
	return pubkey, nil
}
