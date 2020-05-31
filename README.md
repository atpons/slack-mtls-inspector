Slack mTLS PoC
---

https://api.slack.com/authentication/verifying-requests-from-slack#mutual_tls

```console
CRT_FILE=/etc/letsencrypt/live/atpons.example.com/cert.pem KEY_FILE=/etc/letsencrypt/live/atpons.example.com/privkey.pem HOST=atpons.example.com ./inspector
2020/05/31 08:10:45 HOST=atpons.example.com
2020/05/31 08:10:55 request: found tls peer cert n=0 commonName=platform-tls-client.slack.com
2020/05/31 08:10:55 request: found tls peer cert by Slack
2020/05/31 08:10:55 request: found tls peer cert n=1 commonName=DigiCert SHA2 Secure Server CA
2020/05/31 08:10:55 request: SlackSignature=v0=<stripped>
```

