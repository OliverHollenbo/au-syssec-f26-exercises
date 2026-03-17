import json
from mitmproxy import http
from Crypto.PublicKey import RSA


def response(flow: http.HTTPFlow) -> None:
    """Intercepts responses from the server"""
    # replace the server's public key with our own
    if flow.request.path == '/pk/' and flow.request.method == 'GET':
        flow.response = http.Response.make(
            200,
            'TODO: replace this string with the public key in PEM format',
            {'content-type': 'text/plain'},
        )
