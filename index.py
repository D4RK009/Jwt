from flask import Flask, jsonify, request
import jwt
from datetime import datetime

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
        "endpoints": {
            "decode": "/decode_jwt?token=YOUR_JWT_TOKEN"
        },
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

# Vercel handler
def handler(request, **kwargs):
    from io import BytesIO
    from urllib.parse import urlencode
    
    environ = {
        'REQUEST_METHOD': request.get('method', 'GET'),
        'PATH_INFO': request.get('path', '/'),
        'QUERY_STRING': urlencode(request.get('query', {}), doseq=True),
        'SERVER_NAME': 'vercel',
        'SERVER_PORT': '443',
        'HTTP_HOST': request.get('headers', {}).get('host', 'localhost'),
        'wsgi.input': BytesIO(),
        'wsgi.errors': BytesIO(),
        'wsgi.url_scheme': 'https',
        'wsgi.version': (1, 0),
        'wsgi.run_once': True,
        'wsgi.multithread': False,
        'wsgi.multiprocess': False,
    }
    
    # Add headers
    for key, value in request.get('headers', {}).items():
        key = key.upper().replace('-', '_')
        if key not in ('CONTENT_TYPE', 'CONTENT_LENGTH'):
            key = f'HTTP_{key}'
        environ[key] = value
    
    response_data = {}
    
    def start_response(status, headers):
        response_data['status'] = int(status.split(' ')[0])
        response_data['headers'] = dict(headers)
    
    response_body = app(environ, start_response)
    
    return {
        'statusCode': response_data['status'],
        'body': b''.join(response_body).decode('utf-8'),
        'headers': response_data['headers']
    }
