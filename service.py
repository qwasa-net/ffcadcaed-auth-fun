"""
This is a simple HTTP server demonstrating the use of
Kerberos and MTLS authentication mechanisms in Python.

--
GitHub CoPilot was heavily used to generate this code.
"""

import argparse
import base64
import hashlib
import hmac
import http.server
import logging
import os
import ssl

import kerberos
from jose import jwt

log = logging.getLogger()


class Authenticator:
    headers = {}

    @property
    def error_message(self):
        return f"{self.__class__.__name__}: failed"

    @property
    def is_required(self):
        return False

    def __call__(self, handler):
        return None


class IPAuth(Authenticator):
    """This class provides a method for IP-based authentication."""

    def __call__(self, handler):
        return ":".join(map(str, filter(None, handler.client_address)))


class UAAuth(Authenticator):
    """This class provides a method for User-Agent-based authentication."""

    def __call__(self, handler):
        return handler.headers.get("User-Agent")


class APIKeyAuth(Authenticator):
    """This class provides a method for API key authentication."""

    def __init__(self, api_key_header):
        self.api_key_header = api_key_header

    def __call__(self, handler):
        apikey = handler.headers.get(self.api_key_header)
        if not apikey:
            return None
        cn, secret = apikey.split(":")
        self.validate_api_key(cn, secret)
        return cn

    def validate_api_key(self, cn, secret):
        return True


class HMACAuth(Authenticator):
    """"""

    def __init__(self, params, *args, **kwargs):
        self.params = params

    def __call__(self, handler):
        try:
            return self.get_hmac_signed_token(handler)
        except Exception as e:
            log.error("hmac_error=%s", e)
            return None

    def get_hmac_signed_token(self, handler):
        """Get HMAC signed token from the request headers."""

        msgsgn = handler.headers.get(self.params.hmac_header)
        log.debug("headers[%s]=%.255s", self.params.hmac_header, msgsgn)

        if not isinstance(msgsgn, str) or ":" not in msgsgn:
            return None

        msg, sgn = msgsgn.split(":", maxsplit=1)

        # sign to compare
        hsh = hmac.new(
            self.params.hmac_secret.encode(),
            msg.encode(),
            hashlib.sha256,
        )
        expected_sgn = base64.b64encode(hsh.digest()).decode()

        if not hmac.compare_digest(sgn, expected_sgn):
            log.error("hmac_signature_mismatch: %s %s", sgn, expected_sgn)
            return None

        token = base64.b64decode(msg).decode()

        return token  # success


class JWTAuth(Authenticator):
    """This class provides a method for JWT authentication."""

    def __init__(self, params, *args, **kwargs):
        self.params = params

    def __call__(self, handler):
        try:
            return self.get_jwt_token(handler)
        except Exception as e:
            log.error("jwt_error=%s", e)
            return None

    def get_jwt_token(self, handler):
        """Get and decode JWT token from the request headers."""

        auth = handler.headers.get(self.params.jwt_header)
        log.debug("headers[%s]=%.255s", self.params.jwt_header, auth)

        if not isinstance(auth, str) or " " not in auth:
            return None

        schema, token = auth.split(" ", maxsplit=1)
        if schema.lower() != "bearer":
            return None

        jwt_payload = jwt.decode(
            token,
            self.params.jwt_secret,
            algorithms=["HS256"],
            options={"verify_exp": True, "verify_iss": True, "verify_aud": True},
            audience=self.params.service_name,
        )
        log.debug("jwt_payload=%s", jwt_payload)

        username = jwt_payload.get("sub")
        return username  # success


class MTLSAuth(Authenticator):
    """This class provides a method for MTLS authentication."""

    def __init__(self, params, *args, **kwargs):
        self.params = params

    @property
    def is_required(self):
        return self.params.mtls_verify == ssl.CERT_REQUIRED

    def __call__(self, handler):
        username = self.get_client_cert(handler)
        if not self.is_valid(username):
            return None
        return username

    def get_client_cert(self, handler):
        client_dn = None
        if handler.connection:
            client_cert = handler.connection.getpeercert()
            log.debug("client_cert=%s", client_cert)
            if client_cert:
                subj = dict(x[0] for x in client_cert["subject"])
                # client_cn = subj.get("commonName")
                client_dn = "/".join(map(str, subj.values()))
                log.debug("client_dn=%s", client_dn)
        return client_dn

    def is_valid(self, username):
        return username is not None


class KerberosAuth(Authenticator):
    """This class provides a method for Kerberos (SPNEGO) authentication."""

    headers = {"WWW-Authenticate": "Negotiate"}

    def __init__(self, params, *args, **kwargs):
        self.params = params

    @property
    def is_required(self):
        return self.params.krb_principal is not None

    def __call__(self, handler):
        try:
            return self.validate_kerberos_auth(handler)
        except Exception as e:
            log.error("kerberos_error=%s", e)
            return None

    def validate_kerberos_auth(self, handler):
        """Validate Kerberos authentication."""

        # get token
        auth = handler.headers.get(self.params.krb_header)
        log.debug("headers[Authorization]=%.255s", auth)

        if not isinstance(auth, str):
            return None

        schema, token = auth.split(maxsplit=1)
        if schema.lower() != "negotiate":
            return None

        # initialize the Kerberos server-side context for the service
        rc, state = kerberos.authGSSServerInit(self.service_principal)
        if rc != kerberos.AUTH_GSS_COMPLETE:
            return None

        # process the Kerberos token.
        rc = kerberos.authGSSServerStep(state, token)
        if rc != kerberos.AUTH_GSS_COMPLETE:
            return None

        # get the client's username from the Kerberos token
        krb_username = kerberos.authGSSClientUserName(state)
        log.debug("auth krb username=%s", krb_username)

        return krb_username  # success

    @property
    def service_principal(self):
        return self.params.krb_principal or "HTTP"


class HTTPHandler(http.server.BaseHTTPRequestHandler):
    """This class provides a simple HTTP handler."""

    client_ids = {}

    def __init__(self, *args, authers=None, **kwargs):
        self.authers = authers or []
        self.client_ids = {}
        super().__init__(*args, **kwargs)

    @staticmethod
    def wrap_authzers(f):
        """This method wraps authenticators."""

        def wrapper(self, *args, **kwargs):
            for auther in self.authers:
                auth = auther(self)
                if auth is None:
                    log.error("[%s] %s", self.client(), auther.error_message)
                    if auther.is_required:
                        self.send_auth_error(401, auther.headers, auther.error_message)
                        return
                self.client_ids[auther.__class__.__name__] = auth
            f(self, *args, **kwargs)

        return wrapper

    @wrap_authzers
    def do_GET(self):
        """
        Handle GET requests.
        It says hello to the client with all detected client IDs.
        """

        log.info("[%s] GET %s", self.client(), self.path)

        # hello here
        hello = f"Hallo there !!\n\n{self.client(True)}\n\n"
        data = hello.encode("utf-8", errors="ignore")

        # just say it
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.flush_headers()

        self.wfile.write(data)
        self.wfile.flush()

        self.connection.close()

    def client(self, names=False):
        if names:
            frmt, glue = lambda x: f"{x[0]: <16}: {x[1]}", "\n"
        else:
            frmt, glue = lambda x: str(x[1]), " ‖ "
        return glue.join(map(frmt, filter(lambda x: bool(x[1]), self.client_ids.items())))

    def send_auth_error(self, error_code=401, headers=None, message=""):
        log.error("[%s] %s %s", self.client(), error_code, message)
        self.send_response(error_code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()
        self.flush_headers()


class ArgsHandler:
    """Ugly args wrapper for HTTPHandler."""

    def __init__(self, params):
        self.klass = HTTPHandler
        self.params = params
        self.authenticators = [IPAuth(), UAAuth()]
        if params.apikey_header:
            self.authenticators.append(APIKeyAuth(params.apikey_header))
        if params.mtls_verify:
            self.authenticators.append(MTLSAuth(params))
        if params.jwt_secret:
            self.authenticators.append(JWTAuth(params))
        if params.krb_principal:
            self.authenticators.append(KerberosAuth(params))
        if params.hmac_secret:
            self.authenticators.append(HMACAuth(params))

    def __call__(self, *args, **kwargs):
        handler = self.klass(
            *args,
            authers=self.authenticators,
            **kwargs,
        )
        return handler


def run(params):
    """Run the HTTP server."""

    listen = (params.host, params.port)
    handler = ArgsHandler(params)
    httpd = http.server.HTTPServer(listen, handler)

    if params.cert:
        httpd = configure_ssl_context(params, httpd)
        log.info("SSL enabled: %s, %s", params.cert, params.cacert)

    #
    log.info("starting httpd server on %s...", listen)
    httpd.serve_forever()


def configure_ssl_context(args, httpd):
    """Configure SSL context for the HTTP server."""
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    ctx.load_verify_locations(cafile=args.cacert)
    ctx.verify_mode = ssl.CERT_OPTIONAL
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


def main():
    args = parse_args()
    configure_logging(args)
    run(args)


def configure_logging(args):
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger("http.server").setLevel(logging.INFO)
    logging.getLogger("kerberos").setLevel(logging.INFO)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)

    # server bind address
    parser.add_argument("--port", type=int, default=3443)
    parser.add_argument("--host", default="")

    # service name
    parser.add_argument("--service-name", default="SERVICE")

    # SSL
    parser.add_argument("--cert", default=None)
    parser.add_argument("--key", default=None)
    parser.add_argument("--cacert", default=None)

    # client mTLS
    parser.add_argument("--mtls-verify", type=int, default=ssl.CERT_OPTIONAL)

    # krb
    parser.add_argument("--krb-principal", default="HTTP")
    parser.add_argument("--krb-keytab", default=None)
    parser.add_argument("--krb-ccache", default="FILE:/dev/null")
    parser.add_argument("--krb-header", default="Authorization")

    # jwt
    parser.add_argument("--jwt-secret", default="0123456789")
    parser.add_argument("--jwt-header", default="X-JWT")

    # api key
    parser.add_argument("--apikey-header", default="X-API-KEY")

    # hmac
    parser.add_argument("--hmac-header", default="X-HMAC")
    parser.add_argument("--hmac-secret", default="0123456789")

    # debug
    parser.add_argument("--debug", action="store_true")

    args = parser.parse_args()

    if args.krb_keytab:
        os.environ["KRB5_KTNAME"] = args.krb_keytab
    if args.krb_ccache:
        os.environ["KRB5CCNAME"] = args.krb_ccache

    return args


if __name__ == "__main__":
    main()
