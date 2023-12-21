package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
)

var (
	port   = flag.Int("port", 8080, "Port to listen on")
	target = flag.String("target", "", "The target service behind the AuthGate")
	issuer = flag.String("issuer", "", "The oauth2 issuer")
	secret = flag.String("secret", "", "The secret of HS signature")
)

func main() {
	flag.Parse()
	if *issuer == "" && *secret == "" {
		log.Fatal("issuer or secret required")
	}
	if *issuer != "" && *secret != "" {
		log.Fatal("Only one of the issuer and secret parameters is allowed.")
	}
	if *target == "" {
		log.Fatal("target required")
	}
	url, err := url.Parse(*target)
	if err != nil {
		log.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(url)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		//CORS
		if r.Method == http.MethodOptions {
			w.Header().Add("Access-Control-Allow-Methods", "DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT")
			w.Header().Add("Access-Control-Allow-Origin", "*")
			w.WriteHeader(200)
			return
		}
		//authorize
		token := r.Header.Get("Authorization")
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Empty Authorization header!")
			return
		}
		if !validateAuthorization(token) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "401 Unauthorized")
			return
		}
		proxy.ServeHTTP(w, r)
	})
	log.Println("Listen on port:" + strconv.Itoa(*port))
	log.Println("Started successfully")
	err = http.ListenAndServe(":"+strconv.Itoa(*port), nil)
	if err != nil {
		log.Fatalln(err)
	}
}

// TODO
func validateAuthorization(token string) bool {
	return false
}
