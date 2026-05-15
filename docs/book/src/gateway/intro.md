# Gateway

A **gateway** in rama is a service that bridges between an upstream transport
protocol and a backend application protocol. The gateway terminates one side
and translates calls into the other, keeping the application unaware of how
its requests were transported.

The category currently covers:

- [FastCGI](./fastcgi.md) — the classic CGI-over-binary-framing protocol, still
  the lingua franca for PHP-FPM and a handful of polyglot deployments.
