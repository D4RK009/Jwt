from flask import Flask, jsonify, request
import jwt
from datetime import datetime
import json
import sys

app = Flask(__name__)

def decode_jwt(token):
    try:
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        
        if 'exp' in decoded_token:
            exp_time = datetime.utcfromtimestamp(decoded_token['exp'])
            decoded_token['exp'] = exp_time.strftime('%Y-%m-%d %H:%M:%S') 
            if exp_time < datetime.utcnow():
                decoded_token['expired'] = True 
            else:
                decoded_token['expired'] = False
        
        if 'lock_region_time' in decoded_token:
            lock_region_time = datetime.utcfromtimestamp(decoded_token['lock_region_time'])
            decoded_token['lock_region_time'] = lock_region_time.strftime('%Y-%m-%d %H:%M:%S')
        
        return decoded_token
    except jwt.InvalidTokenError:
        return "Invalid token"

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "message": "JWT Decoder API",
        "usage": "/decode_jwt?token=YOUR_JWT_TOKEN",
        "status": "running"
    })

@app.route('/decode_jwt', methods=['GET'])
def api_decode_jwt():
    token = request.args.get('token')
    
    if token:
        decoded = decode_jwt(token)
        return jsonify(decoded)
    else:
        return jsonify({"error": "Token is required"}), 400

# ============================================
# VERCEL SERVERLESS HANDLER - FIXED VERSION
# ============================================

from http.server import BaseHTTPRequestHandler
from io import BytesIO
from urllib.parse import parse_qs, urlparse

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Parse URL and query
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        
        # Flatten query params (take first value)
        query_params = {k: v[0] if v else '' for k, v in query.items()}
        
        # Build WSGI environ for Flask
        environ = {
            'REQUEST_METHOD': 'GET',
            'SCRIPT_NAME': '',
            'PATH_INFO': path,
            'QUERY_STRING': parsed.query,
            'SERVER_NAME': self.headers.get('Host', 'vercel'),
            'SERVER_PORT': '443',
            'HTTP_HOST': self.headers.get('Host', 'vercel'),
            'wsgi.version': (1, 0),
            'wsgi.url_scheme': 'https',
            'wsgi.input': BytesIO(),
            'wsgi.errors': sys.stderr,
            'wsgi.multithread': False,
            'wsgi.multiprocess': False,
            'wsgi.run_once': True,
        }
        
        # Add headers
        for key, value in self.headers.items():
            key_upper = key.upper().replace('-', '_')
            if key_upper not in ('CONTENT_TYPE', 'CONTENT_LENGTH'):
                key_upper = f'HTTP_{key_upper}'
            environ[key_upper] = value
        
        # Capture response
        response_status = [200]
        response_headers = [{}]
        response_body = [b'']
        
        def start_response(status, headers):
            response_status[0] = int(status.split()[0])
            response_headers[0] = dict(headers)
        
        # Run Flask
        try:
            output = app(environ, start_response)
            response_body[0] = b''.join(output)
        except Exception as e:
            response_status[0] = 500
            response_body[0] = json.dumps({"error": str(e)}).encode()
        
        # Send response
        self.send_response(response_status[0])
        for header, value in response_headers[0].items():
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(response_body[0])
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass

# Local development
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
