package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type SlackRequest struct {
	Token     string `json:"token"`
	Challenge string `json:"challenge"`
	Type      string `json:"type"`
}

func main() {
	if err := Inspector(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

func Inspector(_ []string) error {
	hostStr := os.Getenv("HOST")
	log.Printf("HOST=%s", hostStr)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "allow request with only POST", http.StatusMethodNotAllowed)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Println(err)
			http.Error(w, "body read error", http.StatusInternalServerError)
			return
		}
		req := SlackRequest{}
		defer r.Body.Close()
		if err := json.Unmarshal(body, &req); err != nil {
			log.Println(err)
			http.Error(w, "json unmarshal error", http.StatusUnprocessableEntity)
			return
		}
		if req.Challenge != "" {
			log.Println("slack requesting challenge")
			Process(r)
			w.Write([]byte(req.Challenge))
			return
		}
		Process(r)
		w.Write([]byte("OK"))
		return
	})

	server := &http.Server{
		Addr: ":443",
	}
	server.Handler = mux
	caCertPool, _ := x509.SystemCertPool()
	if os.Getenv("ROOT_CA_FILE") != "" {
		log.Println("add ca")
		caFileName := os.Getenv("ROOT_CA_FILE")
		caCert, err := ioutil.ReadFile(caFileName)
		if err != nil {
			return err
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}
	server.TLSConfig = &tls.Config{ClientCAs: caCertPool, ClientAuth: tls.VerifyClientCertIfGiven}
	server.TLSConfig.BuildNameToCertificate()

	return server.ListenAndServeTLS(os.Getenv("CRT_FILE"), os.Getenv("KEY_FILE"))
}

func Process(r *http.Request) {
	defer func() {
		err := recover()
		if err != nil {
			log.Printf("request: abort processing: %+v", err)
		}
	}()

	if r.TLS == nil || len(r.TLS.PeerCertificates) < 1 {
		panic("not have client tls certificates")
	}

	for idx, v := range r.TLS.PeerCertificates {
		log.Printf("request: found tls peer cert n=%d commonName=%s", idx, v.Subject.CommonName)

		// Subject Common Name
		if v.Subject.CommonName == "platform-tls-client.slack.com" {
			log.Printf("request: found tls peer cert by Slack")
		}

		// Subject Alternative Name
		for _, dnsName := range v.DNSNames {
			if dnsName == "platform-tls-client.slack.com" {
				log.Printf("request: found SAN with DNS Name by Slack")
			}
		}
	}

	header := r.Header.Get("X-Slack-Signature")
	log.Printf("request: SlackSignature=%s", header)
}
