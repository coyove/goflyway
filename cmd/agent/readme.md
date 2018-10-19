Agent is not safe, especially HTTP agent.

Use HTTPS whenever possible, e.g.: https://www.hostinger.com/tutorials/ssl/how-to-install-free-ssl-from-lets-encypt-on-shared-hosting


## Why

It serves as a backup method when you really have nothing else to connect to.

It uses MITM to transfer data without encryption to a remote agent server, so basically this ruins all the security protections you had.

Forwarding methods like `fwd://` or `fwds://` are much safer because they just relay the data to your VPS, no one else can see the plain text. (except the VPS provider)

Using it to search google, watch youtube is fine (signed out), but don't use it to access Paypal or anything similar.

## Tutorial

1. Find a free PHP hosting service, e.g.: 000webhost, freehosting
2. Register a website on one of these services, normally you will get a free subdomain, e.g.: example.000webhostapp.com
2. Upload `index.php` to the web root of your website
2. At local, run goflyway `./goflyway -gen-ca` to generate a new certificate, import `ca.pem` into your system cert store
2. At local, run goflyway `./goflyway -up='agent://example.000webhostapp.com:80'` to connect to your website, password is not needed
2. Set your browser's proxy to `127.0.0.1:8100` (you can ONLY use http proxy here)
2. Enjoy

000webhost supports HTTPS connections by default, so it is highly recommended to use: 
```
./goflyway -up='agent://example.000webhostapp.com:443
                                                   ^~~
```
