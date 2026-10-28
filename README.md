## static-server-oidc

Serves a directory of static files on HTTP behind an OpenID Connect identity provider to require login.

Simply configures the default Micronaut static file server and Micronaut Security JWT for OIDC.

### Running from GHCR

Image [`ghcr.io/joe-crawford/static-server-oidc`](https://github.com/joe-crawford/static-server-oidc/pkgs/container/static-server-oidc) is available for amd64 and arm64.

Serve files from `/local/path/to/public_html` on port 80 behind OIDC login:
```bash
docker run -it -p 80:80 -v /local/path/to/public_html:/public_html:ro \
    -e PUBLIC_HTML_ROOT=/public_html \
    -e OAUTH2_CLIENT_ID=<your_client_id> \
    -e OAUTH2_CLIENT_SECRET=<your_client_secret> \
    -e OIDC_ISSUER_URL=<your_oidc_issuer_url> \
    ghcr.io/joe-crawford/static-server-oidc
```

For Entra ID the OIDC issuer URL is `https://login.microsoftonline.com/<your_tenant_id>/v2.0` and the client ID and secret are from the App Registration.
