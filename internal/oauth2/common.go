package oauth2

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var publicKeyCache = make(map[string]PublicKey)

type PublicKey struct {
	Kid          string
	Kty          string
	LastModified int64
	Key          interface{}
}
type jwkBase struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
}

type jwksBase struct {
	Keys []jwkBase `json:"keys"`
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

func GetPublicKeyFromIssuer(issuer string, kid string) (interface{}, error) {
	v, ok := publicKeyCache[kid]
	if ok && time.Now().Unix()-v.LastModified < 300 {
		return v.Key, nil
	}
	jwks, err := GetJwksFromIssuer(issuer)
	if err != nil {
		return nil, err
	}
	var data jwksBase
	var base jwkBase
	err = json.Unmarshal([]byte(jwks), &data)
	if err != nil {
		return nil, err
	}
	//determine the alg for the kid
	if kid == "" {
		base = data.Keys[0]
	} else {
		for _, e := range data.Keys {
			if e.Kid == kid {
				base = e
				break
			}
		}
	}
	if base.Kty == "" {
		return nil, errors.New("unable to determin the kty")
	}
	var k interface{}
	if strings.EqualFold("RSA", base.Kty) {
		k, err = GetRsaPublicKey([]byte(jwks), kid)
		if err != nil {
			return nil, err
		}
	} else if strings.EqualFold("EC", base.Kty) {
		k, err = GetEccPublicKey([]byte(jwks), kid)
		if err != nil {
			return nil, err
		}
	} else if strings.EqualFold("OKP", base.Kty) {
		k, err = GetOKPPublicKey([]byte(jwks), kid)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("not support kty:" + base.Kty)
	}
	var pubkey PublicKey
	pubkey.Key = k
	pubkey.Kid = kid
	pubkey.Kty = base.Kty
	pubkey.LastModified = time.Now().Unix()
	publicKeyCache[kid] = pubkey
	return k, nil
}
