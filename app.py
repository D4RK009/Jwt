import jwt
from datetime import datetime
from flask import Flask, jsonify, request

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

# Vercel serverless handler
def handler(request, **kwargs):
    from werkzeug.wrappers import Request
    from werkzeug.serving import run_wsgi_app
    
    with app.request_context(request.get('environ', {})):
        return app(request.get('environ', {}), lambda status, headers: None)

# For local development
if __name__ == '__main__':
    app.run(debug=True)
