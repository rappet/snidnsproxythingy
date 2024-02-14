# SNI DNS Proxy Thingy

> ## TL;DR
> 1. get TCP session over IPv4
> 2. extract SNI header
> 3. lookup destination IPv6 using DNS
> 4. open connection with destination server and copy stream

SNI proxy without config  (almost)

```bash
# proxy for example.com, foo.example.com, ...
# will listen on 443
# maybe add a HTTP server on the same host to tell clients to use HTTPS
snidnsproxythingy --allow-hostname example.com
```