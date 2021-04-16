# Auth-Server
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
