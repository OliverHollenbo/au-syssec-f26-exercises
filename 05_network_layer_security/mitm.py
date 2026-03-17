from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    """Intercepts responses from the server"""
    # replace the server's public key with our own
    if flow.request.path == '/view_secrets/' and flow.request.method == 'GET':
        flow.response = http.Response.make(
            200,
            'TODO: insert your string here',
            {'content-type': 'text/plain'},
        )
