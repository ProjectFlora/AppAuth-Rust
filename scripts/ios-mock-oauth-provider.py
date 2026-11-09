#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit


class OAuthProvider(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.authorization = None


class OAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        request = urlsplit(self.path)
        if request.path != "/authorize":
            self.respond(404, b"")
            return

        parameters = parse_qs(request.query, keep_blank_values=True)
        client_id = self.single(parameters, "client_id")
        redirect_uri = self.single(parameters, "redirect_uri")
        state = self.single(parameters, "state")
        challenge = self.single(parameters, "code_challenge")
        redirect = urlsplit(redirect_uri) if redirect_uri else None
        if (
            client_id != "ios-smoke-client"
            or self.single(parameters, "response_type") != "code"
            or self.single(parameters, "scope") != "profile"
            or self.single(parameters, "code_challenge_method") != "S256"
            or not state
            or not challenge
            or redirect is None
            or redirect.scheme != "appauth-smoke"
            or redirect.netloc != "oauth"
            or redirect.path != "/callback"
        ):
            self.respond(400, b"Invalid authorization request")
            return

        self.server.authorization = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "challenge": challenge,
        }
        callback = urlsplit(redirect_uri)
        callback = callback._replace(
            query=urlencode({"code": "mock-authorization-code", "state": state})
        )
        self.respond(
            302,
            b"",
            {"Location": urlunsplit(callback)},
        )

    def do_POST(self):
        if self.path != "/token":
            self.respond(404, b"")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 16 * 1024:
                raise ValueError("invalid request size")
            body = self.rfile.read(length).decode("ascii")
            parameters = parse_qs(body, keep_blank_values=True, strict_parsing=True)
        except (UnicodeDecodeError, ValueError):
            self.respond(400, b"Invalid token request")
            return

        authorization = self.server.authorization
        verifier = self.single(parameters, "code_verifier")
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode("ascii")
            if verifier
            else None
        )
        if (
            authorization is None
            or self.single(parameters, "grant_type") != "authorization_code"
            or self.single(parameters, "code") != "mock-authorization-code"
            or self.single(parameters, "redirect_uri") != authorization["redirect_uri"]
            or self.single(parameters, "client_id") != authorization["client_id"]
            or challenge != authorization["challenge"]
        ):
            self.respond(400, b"Invalid token request")
            return

        self.respond(
            200,
            json.dumps(
                {
                    "access_token": "mock-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "mock-refresh-token",
                    "scope": "profile",
                }
            ).encode(),
            {"Content-Type": "application/json"},
        )

    @staticmethod
    def single(parameters, name):
        values = parameters.get(name, [])
        return values[0] if len(values) == 1 else None

    def respond(self, status, body, headers=None):
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        print(format_string % args, flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port-file", required=True)
    args = parser.parse_args()

    server = OAuthProvider(("127.0.0.1", 0), OAuthHandler)
    port_file = Path(args.port_file)
    port_file.parent.mkdir(parents=True, exist_ok=True)
    port_file.write_text(f"{server.server_port}\n", encoding="ascii")
    print(f"mock OAuth provider listening on 127.0.0.1:{server.server_port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
