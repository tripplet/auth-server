# Auth-Server
![CI](https://github.com/tripplet/auth-server/actions/workflows/ci.yml/badge.svg)

Simple authentication server for the [nginx auth request module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)

```
auth-server 1.3.0
Usage: auth-server [OPTIONS] <--secret <SECRET>|--secret-file <SECRET_FILE>>

Options:
      --listen <LISTEN>
          Address to listen on like 127.0.0.1:14314, can also be a unix socket 
          (e.g. unix:/tmp/auth-server.sock) [env: LISTEN=] [default: 127.0.0.1:14314]
      --systemd-activation-idle <SYSTEMD_ACTIVATION_IDLE>
          Timeout after which the programs waits for new requests afterwards it exists 
          (used for systemd socket activation) [env: SYSTEMD_ACTIVATION_IDLE=]
      --socket-group <SOCKET_GROUP>
          Set the group of the unix socket file to the given group [env: SOCKET_GROUP=]
      --secret <SECRET>
          Secret to use [env: SECRET]
      --secret-file <SECRET_FILE>
          Read secret from file [env: SECRET_FILE=]
      --cookie-name <COOKIE_NAME>
          The name of the cookie [env: COOKIE_NAME=] [default: REQUEST_AUTHORIZATION_TOKEN]
  -v, --verbose
          Verbose mode
  -h, --help
          Print help
  -V, --version
          Print version
```

## Example nginx configuration

```nginx
server {
    ...

    location / {
        auth_request /internal-cookie-auth;

        include proxy_pass;
        proxy_pass http://localhost:8080;
    }

    location /internal-cookie-auth {
        internal;

        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        include proxy_pass;
        proxy_pass http://unix:/run/auth-server/listen.sock:/check/SUBJECTNAME;
    }
}
```
