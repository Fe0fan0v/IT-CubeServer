from flask import Flask, request, jsonify, make_response
from base_work import *
import uuid
import jwt
from datetime import datetime, timedelta
from functools import wraps
from users import User

app = Flask(__name__)
app.config['SECRET_KEY'] = uuid.uuid4().hex


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
            user = user_find('public_id', data)
            current_user = User(user['public_id'], user['email'], user['password'])
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


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email, password = request.json['email'], request.json['password']
        if not request.json:
            return make_response(jsonify({'error': 'Empty request'}), 400)
        elif not all(key in request.json for key in
                     ['email', 'password']):
            return make_response(jsonify({'error': 'Bad request'}), 400)
        elif user_find('email', request.json['email']):
            return make_response(jsonify({'error': 'User already exists'}), 409)
        else:
            hashed_password = generate_password_hash(password)
            user = User(str(uuid.uuid4()), email, hashed_password)
            add_user(user.email, user.password, user.public_id)
            return make_response(jsonify({'status': 'OK'}), 200)


@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if request.method == 'POST':
        email, password = request.json['email'], request.json['password']
        if not request.json:
            return make_response(jsonify({'error': 'Empty request'}), 400)
        elif not all(key in request.json for key in
                     ['email', 'password']):
            return make_response(jsonify({'error': 'Bad request'}), 400)
        user_data = user_find('email', email)
        if not user_data:
            return make_response(jsonify({'error': 'User not exists'}), 403)
        else:
            user = User(user_data['public_id'], user_data['email'], user_data['password'])
            if check_password_hash(user_find('email', email)['password'], password):
                token = encode_auth_token(user.public_id)
                return make_response(jsonify({'token': token.decode('utf-8')}), 200)
            return make_response(jsonify({'error': 'wrong password'}), 403)


@app.route('/profile', methods=['GET', 'POST'])
@token_required
def profile(current_user):
    return make_response(jsonify({'email': current_user.email}), 200)


if __name__ == '__main__':
    app.run()
