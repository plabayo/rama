# nginx `fastcgi_params` — de-facto FastCGI environment

The FastCGI 1.0 specification deliberately defers the *meaning* of name-value
pairs to CGI. In practice the FastCGI ecosystem (php-fpm, Python `flup`,
mod_authnz_fcgi, etc.) is built around the variable set that **nginx** and
**Apache** historically send. This file curates that de-facto contract.

## nginx `fastcgi_params` (canonical defaults)

Source: <https://github.com/nginx/nginx/blob/master/conf/fastcgi_params>

```nginx
fastcgi_param  QUERY_STRING       $query_string;
fastcgi_param  REQUEST_METHOD     $request_method;
fastcgi_param  CONTENT_TYPE       $content_type;
fastcgi_param  CONTENT_LENGTH     $content_length;

fastcgi_param  SCRIPT_NAME        $fastcgi_script_name;
fastcgi_param  REQUEST_URI        $request_uri;
fastcgi_param  DOCUMENT_URI       $document_uri;
fastcgi_param  DOCUMENT_ROOT      $document_root;
fastcgi_param  SERVER_PROTOCOL    $server_protocol;
fastcgi_param  REQUEST_SCHEME     $scheme;
fastcgi_param  HTTPS              $https if_not_empty;

fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;

fastcgi_param  REMOTE_ADDR        $remote_addr;
fastcgi_param  REMOTE_PORT        $remote_port;
fastcgi_param  SERVER_ADDR        $server_addr;
fastcgi_param  SERVER_PORT        $server_port;
fastcgi_param  SERVER_NAME        $server_name;

# PHP only, required if PHP was built with --enable-force-cgi-redirect
fastcgi_param  REDIRECT_STATUS    200;
```

In addition, sites that talk to PHP-FPM typically set `SCRIPT_FILENAME` and
`PATH_TRANSLATED` from the request path (php-fpm refuses to run a script
without `SCRIPT_FILENAME`):

```nginx
fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;
fastcgi_param  PATH_TRANSLATED    $document_root$fastcgi_path_info;
```

## Variables `rama-fastcgi` emits (client side, `http/convert.rs`)

`rama-fastcgi` is **proxy-first**: when used as the FastCGI client (talking to
a backend like php-fpm) it emits every variable below that it can derive
from the incoming HTTP request:

| Variable | Source | Notes |
|---|---|---|
| `REQUEST_METHOD`     | HTTP method                 | RFC 3875 §4.1.12 |
| `REQUEST_URI`        | full path + `?query`        | de-facto (nginx) |
| `DOCUMENT_URI`       | request path (no query)     | de-facto (nginx) |
| `SCRIPT_NAME`        | request path                | RFC 3875 §4.1.13 — see "Script name / path info split" below |
| `PATH_INFO`          | empty by default            | RFC 3875 §4.1.5 |
| `QUERY_STRING`       | URI query (may be empty)    | RFC 3875 §4.1.7 |
| `SERVER_PROTOCOL`    | `HTTP/1.0` / `HTTP/1.1` / `HTTP/2` | RFC 3875 §4.1.16 |
| `REQUEST_SCHEME`     | `http` or `https`           | de-facto (nginx) |
| `HTTPS`              | `on` when scheme is HTTPS   | de-facto — Laravel/WordPress URL generation reads this |
| `SERVER_NAME`        | from `Host` header          | RFC 3875 §4.1.14 |
| `SERVER_PORT`        | from `Host` header or socket | RFC 3875 §4.1.15 — `443` for HTTPS, `80` otherwise |
| `SERVER_ADDR`        | local socket address        | de-facto (nginx) |
| `REMOTE_ADDR`        | peer socket address         | RFC 3875 §4.1.8 |
| `REMOTE_PORT`        | peer socket port            | de-facto (nginx) |
| `GATEWAY_INTERFACE`  | `CGI/1.1`                   | RFC 3875 §4.1.4 — **must** be `CGI/1.1` (some scripts string-match) |
| `CONTENT_TYPE`       | request `Content-Type`      | RFC 3875 §4.1.3 |
| `CONTENT_LENGTH`     | request body length         | RFC 3875 §4.1.2 |
| `REDIRECT_STATUS`    | `200`                       | required by php-fpm when built with `--enable-force-cgi-redirect` (default) |
| `HTTP_*`             | every non hop-by-hop header | RFC 3875 §4.1.18 |

### Hop-by-hop headers (NOT mapped to `HTTP_*`)

Per RFC 7230 §6.1: `connection`, `keep-alive`, `proxy-connection`,
`transfer-encoding`, `te`, `trailer`, `upgrade`. Also `host`,
`content-type`, and `content-length` get their own dedicated variables.

### Script name / path info split

RFC 3875 §4.1.13 says `SCRIPT_NAME` is the leading portion of the URI
that identifies the script, and §4.1.5 says `PATH_INFO` is the trailing
portion. The *gateway* (web server) is responsible for splitting — it's
configuration, not protocol.

`rama-fastcgi` defaults to `SCRIPT_NAME = <full path>` and `PATH_INFO = ""`,
which is correct for backends that route on the full path (most modern
frameworks). For traditional PHP-style routing where `SCRIPT_NAME`
identifies a `.php` file and `PATH_INFO` is what follows, configure the
splitter explicitly (e.g. `try_files` + regex in nginx, or a custom
`ScriptNameSplitter` in rama).

### `SCRIPT_FILENAME` and `PATH_TRANSLATED`

These map a URL path to a filesystem path on the FastCGI application's
host. They are **not** derivable from the HTTP request alone — they
require a `document_root` configuration. `rama-fastcgi` does not emit
them by default; users who target php-fpm must provide them via their own
parameter-injection layer.

## References

- FastCGI 1.0 — [`fastcgi_spec.txt`](fastcgi_spec.txt)
- RFC 3875 — The Common Gateway Interface (CGI) Version 1.1 ([`rfc3875.txt`](rfc3875.txt))
- nginx fastcgi_params — <https://github.com/nginx/nginx/blob/master/conf/fastcgi_params>
- PHP-FPM `REDIRECT_STATUS` — <https://www.php.net/manual/en/security.cgi-bin.force-redirect.php>
- mod_authnz_fcgi (Authorizer role) — <https://httpd.apache.org/docs/2.4/mod/mod_authnz_fcgi.html>
