from flask import Flask, request, jsonify, make_response
from base_work import *
import uuid
import jwt
from datetime import datetime, timedelta
from functools import wraps
from users import User
from flasgger import Swagger
from flasgger.utils import swag_from

app = Flask(__name__)
app.config['SECRET_KEY'] = uuid.uuid4().hex
app.config['SWAGGER'] = {
    'title': 'ITCubeMiass',
    "specs_route": "/swagger/"
}
swagger = Swagger(app)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        if not token:
            return make_response(jsonify({'message': 'token is missing'}), 401),
        try:
            data = decode_auth_token(token)
            current_user = find_in_base('public_id', data)
        except Exception:
            return make_response(jsonify({'message': 'token is invalid'}), 503)
        return f(current_user, *args, **kwargs)
    return decorator


def encode_auth_token(public_id):
    try:
        payload = {
            'exp': datetime.utcnow() + timedelta(minutes=10),
            'iat': datetime.utcnow(),
            'sub': public_id
        }
        return jwt.encode(
            payload,
            app.config.get('SECRET_KEY')
        )
    except Exception as e:
        return e


def decode_auth_token(auth_token):
    try:
        payload = jwt.decode(auth_token, app.config['SECRET_KEY'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'


@app.route('/', methods=['GET'])
@swag_from('swagger/main.yaml')
def index():
    return make_response('IT Cube Miass', 200)


@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        email, password = request.json['email'], request.json['password']
        if not request.json:
            return make_response(jsonify({'error': 'Empty request'}), 400)
        elif not all(key in request.json for key in
                     ['email', 'password']):
            return make_response(jsonify({'error': 'Bad request'}), 400)
        elif find_in_base('email', request.json['email']):
            return make_response(jsonify({'error': 'User already exists'}), 409)
        else:
            hashed_password = generate_password_hash(password)
            user = User(str(uuid.uuid4()), email, hashed_password)
            user.add_to_base()
            return make_response(jsonify({'status': 'OK'}), 201)


@app.route('/auth', methods=['POST'])
@swag_from('swagger/auth.yaml')
def auth():
    if request.method == 'POST':
        email, password = request.json['email'], request.json['password']
        if not request.json:
            return make_response(jsonify({'error': 'Empty request'}), 400)
        elif not all(key in request.json for key in
                     ['email', 'password']):
            return make_response(jsonify({'error': 'Bad request'}), 400)
        user = find_in_base('email', email)
        if not user:
            return make_response(jsonify({'error': 'User not exists'}), 403)
        elif check_password_hash(user.password, password):
                token = encode_auth_token(user.public_id)
                return make_response(jsonify({'token': token.decode('utf-8')}), 201)
        return make_response(jsonify({'error': 'wrong password'}), 403)


@app.route('/profile', methods=['POST'])
@token_required
def profile(current_user):
    return make_response(jsonify({'email': current_user.email}), 200)


if __name__ == '__main__':
    app.run()