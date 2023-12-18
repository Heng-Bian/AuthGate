package main

import (
	"fmt"
	"log"

	"github.com/Heng-Bian/AuthGate/internal/oauth2"
	"github.com/golang-jwt/jwt/v5"
)

const tokenString = "eyJraWQiOiJhaWdjX3VhYSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJhZG1pbiIsImF1ZCI6ImFpZ2MiLCJuYmYiOjE3MDI3OTU0MjksInJvbGUiOlsiMTIzNDU2Il0sInNjb3BlIjpbXSwiaXNzIjoiaHR0cDovLzEwLjE5LjMyLjkzOjgwOTIvdWFhIiwidGVuYW50SWQiOiJkZWZhdWx0IiwiZXhwIjoxNzM0MzMxNDI5LCJpYXQiOjE3MDI3OTU0Mjl9.zm_zNe1-wJxMH7XAQTBnHR99LM4qCANSnvmMov-4gAo_JDbdVh1EEZthJqylR3hI0GP4KbS3o7zy9UMIJu7gLBArn_0qRpy3x4U2oVea99t02e8jDxSBpNY6wgryU2iXqDlmCeH626HJ3l_9wiI2a1e8z-n-tAkgyZK0KQPhl0uQ3TBc4BvzrA-td-w3Gj4zTwcPF8iREVPaOjdD-f_RROQIojlINoWw7Stw-JgQNJ1Y-dbzvpkjaIbw31bmquHuZW2DViY3eao-MWrwXDGm7rPnZrJH7_YHu0DfbgbApFpVh26Lgxdzf2YH3ml0ejnq1w5W2R_a-vfGRKkJl-MB8Q"

func main() {

	// Parse public key
	jwk := `{
		"keys": [
			{
				"kty": "RSA",
				"e": "AQAB",
				"kid": "aigc_uaa",
				"n": "z1vGiY_df3ipESBZyw_NM5vO1Hh19_5bVmyhp_Jm7Lt6lNP_vUd853bS_mAxUIr0NTIyRp4GppYm7ZfZfcgdnclz1ry25_739cOU0ZjrD-l3emgEmT_JPR49BHi0GUz8QZtrgybJMdkxAzoOhnpIf2aXtyLOZGXFZJVs0hRZ0QLo1UDenrvKj_QUB91eYDKL6TW7RWs5OzRS5LgNcbpe1ZhS1zGuNw-Nm8cIzLYTwUlVFWngVWvYbSfOYJd9Izd3GIAZbiuN11elQXxstCRKn-1zVnbjoUBjH59ecsQpBlgxMGfZi3mlMaqgsKJz0Kqw-2A2wntmSY2AQZTHcPfGZQ"
			}
		]
	}`
	var err error
	jwk, err = oauth2.GetJwksFromIssuer("YOUR_ISSUER_URL")
	fmt.Print(err)
	publicKey, err := oauth2.ParseJWKS([]byte(jwk), "")
	if err != nil {
		fmt.Println("Error parsing public key:", err)
		return
	}

	// Now you can use the publicKey in your application
	fmt.Println("Public Key:", publicKey)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return publicKey, nil
	})
	if err != nil {
		log.Fatal(err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		fmt.Println(claims["aud"], claims["nbf"])
	} else {
		fmt.Println(err)
	}
	fmt.Print(token.Valid)

}
