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
# VERCEL SERVERLESS HANDLER
# ============================================

def handler(event, context):
    """Vercel serverless function entry point"""
    from io import BytesIO
    from urllib.parse import urlencode
    
    # Get request details from event
    method = event.get('httpMethod', 'GET')
    path = event.get('path', '/')
    query = event.get('queryStringParameters') or {}
    headers = event.get('headers') or {}
    body = event.get('body') or ''
    
    if event.get('isBase64Encoded') and body:
        import base64
        body = base64.b64decode(body).decode('utf-8')
    
    # Build query string
    query_string = urlencode(query, doseq=True) if query else ''
    
    # Build WSGI environ
    environ = {
        'REQUEST_METHOD': method,
        'SCRIPT_NAME': '',
        'PATH_INFO': path,
        'QUERY_STRING': query_string,
        'SERVER_NAME': headers.get('host', 'vercel'),
        'SERVER_PORT': headers.get('x-forwarded-port', '443'),
        'HTTP_HOST': headers.get('host', 'vercel'),
        'CONTENT_TYPE': headers.get('content-type', ''),
        'CONTENT_LENGTH': str(len(body.encode())) if body else '0',
        'wsgi.version': (1, 0),
        'wsgi.url_scheme': headers.get('x-forwarded-proto', 'https'),
        'wsgi.input': BytesIO(body.encode() if body else b''),
        'wsgi.errors': BytesIO(),
        'wsgi.multithread': False,
        'wsgi.multiprocess': False,
        'wsgi.run_once': True,
    }
    
    # Add other headers
    for key, value in headers.items():
        key_lower = key.lower()
        if key_lower not in ('content-type', 'content-length', 'host'):
            environ[f'HTTP_{key.upper().replace("-", "_")}'] = value
    
    # Response collector
    response_status = [200]
    response_headers = [{}]
    
    def start_response(status, headers_list):
        response_status[0] = int(status.split()[0])
        response_headers[0] = {k: v for k, v in headers_list}
    
    # Execute Flask app
    response_body = app(environ, start_response)
    
    # Collect body
    body_content = b''.join(response_body).decode('utf-8')
    
    return {
        'statusCode': response_status[0],
        'headers': response_headers[0],
        'body': body_content
    }

# Local development
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
