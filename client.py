"""
Simple HTTP client to test mTLS and SPNEGO authentication.

--
GitHub CoPilot was heavily used to generate this code.
"""

import argparse
import base64
import hashlib
import hmac
import ssl
import time

import gssapi
import httpx
import httpx_gssapi
from jose import jwt


def make_request(args):

    headers = {}
    certs, auth, verify_ca = None, None, None

    # mTLS
    if args.cert and args.key:
        certs = (args.cert, args.key)

    # SPNEGO
    if args.negotiate:
        auth = create_spnego_auth(args.service_name, args.realm, args.principal)

    # api key
    if args.apikey_header:
        headers[args.apikey_header] = f"{args.username}:{int(time.time())}"

    # jwt
    if args.jwt_secret or args.jwt_private_key:
        token = generate_jwt_token(args)
        headers[args.jwt_header] = "bearer " + token

    # hmac
    if args.hmac_secret:
        message = base64.b64encode(args.username.encode("utf8")).decode()
        hmacsign = generate_hmac_signature(args.hmac_secret, message)
        headers[args.hmac_header] = f"{message}:{hmacsign}"

    # server cert verification
    if args.cacert:
        verify_ca = ssl.create_default_context(cafile=args.cacert)

    # set up client and make request
    with httpx.Client(auth=auth, verify=verify_ca, cert=certs) as client:
        response = client.get(args.url, headers=headers)

    return response


def create_spnego_auth(service_name, realm, principal):
    my_name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
    target_name = gssapi.Name(service_name, gssapi.NameType.kerberos_principal)
    creds = gssapi.Credentials(name=my_name, usage="initiate")
    auth = httpx_gssapi.HTTPSPNEGOAuth(target_name=target_name, creds=creds)
    return auth


def generate_hmac_signature(secret_key, message):
    hsh = hmac.new(
        secret_key.encode(),
        message.encode(),
        hashlib.sha256,
    )
    signature = base64.b64encode(hsh.digest()).decode()
    return signature


def generate_jwt_token(args):

    payload = {
        "sub": args.username,
        "aud": args.service_name.split("/")[0],
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }

    if args.jwt_private_key:
        secret_key = open(args.jwt_private_key).read()
        algorithm = "RS256"
    else:
        secret_key = args.jwt_secret
        algorithm = "HS256"

    token = jwt.encode(
        payload,
        secret_key,
        algorithm=algorithm,
        headers={"typ": "JWT", "alg": algorithm},
    )

    return token


def main():
    """Parse arguments and do the do."""

    args = read_args()

    rsp = make_request(args)

    if args.debug:
        print_response_details(rsp, headers=args.headers)

    print(rsp.text)


def print_response_details(rsp, headers=False):

    print(f"> [{rsp.request.method}] {rsp.request.url}")
    if headers:
        for k, v in rsp.request.headers.items():
            print(f"> {k}: {v:.80s}")
    print("")

    print(f"< [{rsp.status_code}]")
    if headers:
        for k, v in rsp.headers.items():
            print(f"< {k}: {v:.80s}")
    print("")


def read_args():

    parser = argparse.ArgumentParser()
    parser.add_argument("url", type=str)

    # client username
    parser.add_argument("--username", default="client")

    # server cert verification
    parser.add_argument("--cacert", type=str, default=None)

    # mTLS
    parser.add_argument("--cert", type=str, default=None)
    parser.add_argument("--key", type=str, default=None)

    # SPNEGO
    parser.add_argument("--negotiate", action="store_true")
    parser.add_argument("--service-name", default=None)
    parser.add_argument("--realm", default=None)
    parser.add_argument("--principal", default="user")

    # jwt
    parser.add_argument("--jwt-secret", default=None)
    parser.add_argument("--jwt-private-key", default=None)
    parser.add_argument("--jwt-header", default="X-JWT")

    # hmac
    parser.add_argument("--hmac-header", default="X-HMAC")
    parser.add_argument("--hmac-secret", default="0123456789")

    # api key
    parser.add_argument("--apikey-header", default="X-API-KEY")

    # debug
    parser.add_argument("--debug", "-v", action="store_true")
    parser.add_argument("--headers", "-i", action="store_true")

    args, argv = parser.parse_known_args()
    return args


if __name__ == "__main__":
    main()
