# Auth-Server
![CI](https://github.com/tripplet/auth-server/actions/workflows/ci.yml/badge.svg)

Simple authentication server for the [nginx auth request module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)

```
auth-server 1.0.0
Service for authenticating requests from nginx (ngx_http_auth_request_module).

USAGE:
    auth-server [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v, --verbose    Verbose mode

OPTIONS:
        --cookie-name <cookie-name>      The name of the cookie [env: COOKIE_NAME=]  [default:
                                         REQUEST_AUTHORIZATION_TOKEN]
        --listen <listen>                Address to listen on, can also be a unix socket (unix:/tmp/auth-server.sock)
                                         [env: LISTEN=]  [default: 127.0.0.1:14314]
        --secret <secret>                Secret secret to use [env: SECRET]
        --secret-file <secret-file>      Read secret from file [env: SECRET_FILE]
        --socket-group <socket-group>    Set the group of the unix socket file to the given group [env: SOCKET_GROUP=]
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
