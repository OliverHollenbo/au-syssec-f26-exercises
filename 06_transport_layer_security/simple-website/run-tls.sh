#!/bin/bash
FLASK_APP=main flask run --host 0.0.0.0 --port 443 --cert=cert.pem --key=key.pem
