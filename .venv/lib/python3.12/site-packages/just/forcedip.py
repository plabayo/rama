"""
This module implements a set of requests TransportAdapter, PoolManager,
ConnectionPool and HTTPSConnection with one goal only:
* to use a specific IP address when connecting via SSL to a web service without
running into SNI trouble.
The usual technique to force an IP address on an HTTP connection with Requests
is (assuming I want http://example.com/some/path on IP 1.2.3.4):
requests.get("http://1.2.3.4/some/path", headers={'Host': 'example.com'})
this is useful if I want to specifically test how 1.2.3.4 is responding; for
instance, if example.com is DNS round-robined to several IP
addresses and I want to hit one of them specifically.
This also works for https requests if using Python <2.7.9 because older
versions don't do SNI and thus don't pass the requested hostname as part of the
SSL handshake.
However, Python >=2.7.9 and >=3.4.x conveniently added SNI support, breaking
this way of connecting to the IP, because the IP address embedded in the URL
*is* passed as part of the SSL handshake, causing errors (mainly, the server
returns a 400 Bad Request because the SNI host 1.2.3.4 doesn't match the one in
the HTTP headers example.com).
The "easiest" way to achieve this is to force the IP address at the lowest
possible level, namely when we do socket.create_connection. The rest of the
"stack" is given the actual hostname. So the sequence is:
1- Open a socket to 1.2.3.4
2- SSL wrap this socket using the hostname.
3- Do the rest of the HTTPS traffic, headers and all over this socket.
Unfortunately Requests hides the socket.create_connection call in the deep
recesses of urllib3, so the specified chain of classes is needed to propagate
the given dest_ip value all the way down the stack.
Because this applies to a very limited set of circumstances, the overridden
code is very simplistic and eschews many of the nice checks Requests does for
you.
Specifically:
- It ONLY handles HTTPS.
- It does NO certificate verification (which would be pointless)
- Only tested with Requests 2.2.1 and 2.9.1.
- Does NOT work with the ancient urllib3 (1.7.1) shipped with Ubuntu 14.04.
  Should not be an issue because Ubunt 14.04 has older Python which doesn't do
  SNI.
How to use it
=============
It's like any other transport adapter. Just pass the IP address that
connections to the given URL prefix should use.
session = requests.Session()
session.mount("https://example.com", ForcedIPHTTPSAdapter(dest_ip='1.2.3.4'))
response = session.get(
    '/some/path', headers={'Host': 'example.com'}, verify=False)
"""
# Note this module will ImportError if there's no sane requests/urllib
# combination available so the adapter won't work, and it's up to the caller to
# decide what to do. The caller can, for instance, check the Python version and
# if it's <2.7.9 decide to use the old "http://$IP/ technique. If Python is
# >2.7.9 and the adapter doesn't work, unfortunately, there's nothing that can
# be done :(
from distutils.version import StrictVersion
from socket import error as SocketError, timeout as SocketTimeout

import requests
from requests.adapters import HTTPAdapter

from requests.packages.urllib3.poolmanager import (
    PoolManager,
    HTTPSConnectionPool,
)
from requests.packages.urllib3.exceptions import ConnectTimeoutError

try:
    # For requests 2.9.x
    from requests.packages.urllib3.util import connection
    from requests.packages.urllib3.exceptions import NewConnectionError
except ImportError:
    # For requests  <= 2.2.x
    import socket as connection
    from socket import error as NewConnectionError
# Requests older than 2.4.0's VerifiedHHTPSConnection is broken and doesn't
# properly use _new_conn. On these versions, use UnverifiedHTTPSConnection
# instead.
if StrictVersion(requests.__version__) < StrictVersion("2.4.0"):
    from requests.packages.urllib3.connection import UnverifiedHTTPSConnection as HTTPSConnection
else:
    from requests.packages.urllib3.connection import HTTPSConnection


class ForcedIPHTTPSAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.dest_ip = kwargs.pop("dest_ip", None)
        super(ForcedIPHTTPSAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **pool_kwargs):
        pool_kwargs["dest_ip"] = self.dest_ip
        self.poolmanager = ForcedIPHTTPSPoolManager(*args, **pool_kwargs)


class ForcedIPHTTPSPoolManager(PoolManager):
    def __init__(self, *args, **kwargs):
        self.dest_ip = kwargs.pop("dest_ip", None)
        super(ForcedIPHTTPSPoolManager, self).__init__(*args, **kwargs)

    def _new_pool(self, scheme, host, port, request_context=None):
        assert scheme == "https"
        kwargs = self.connection_pool_kw.copy()
        kwargs["dest_ip"] = self.dest_ip
        return ForcedIPHTTPSConnectionPool(host, port, **kwargs)


class ForcedIPHTTPSConnectionPool(HTTPSConnectionPool):
    def __init__(self, *args, **kwargs):
        self.dest_ip = kwargs.pop("dest_ip", None)
        super(ForcedIPHTTPSConnectionPool, self).__init__(*args, **kwargs)

    def _new_conn(self):
        self.num_connections += 1

        actual_host = self.host
        actual_port = self.port
        if self.proxy is not None:
            actual_host = self.proxy.host
            actual_port = self.proxy.port

        conn_kw = getattr(self, "conn_kw", {}).copy()
        conn_kw["dest_ip"] = self.dest_ip
        conn = ForcedIPHTTPSConnection(
            host=actual_host, port=actual_port, timeout=self.timeout.connect_timeout, strict=self.strict, **conn_kw
        )
        pc = self._prepare_conn(conn)
        return pc

    def __str__(self):
        return "%s(host=%r, port=%r, dest_ip=%s)" % (type(self).__name__, self.host, self.port, self.dest_ip)


class ForcedIPHTTPSConnection(HTTPSConnection, object):
    def __init__(self, *args, **kwargs):
        self.dest_ip = kwargs.pop("dest_ip", None)
        super(ForcedIPHTTPSConnection, self).__init__(*args, **kwargs)

    def _new_conn(self):
        extra_kw = {}
        if self.source_address:
            extra_kw["source_address"] = self.source_address

        if getattr(self, "socket_options", None):
            extra_kw["socket_options"] = self.socket_options

        dest_host = self.dest_ip if self.dest_ip else self.host

        try:
            conn = connection.create_connection((dest_host, self.port), self.timeout, **extra_kw)

        except SocketTimeout as e:
            raise ConnectTimeoutError(
                self, "Connection to %s timed out. (connect timeout=%s)" % (self.host, self.timeout)
            )

        except SocketError as e:
            raise NewConnectionError(self, "Failed to establish a new connection: %s" % e)

        return conn
