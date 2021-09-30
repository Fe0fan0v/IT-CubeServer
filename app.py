from flask import Flask, request, jsonify, make_response
import uuid
import jwt
from datetime import datetime, timedelta
from functools import wraps
from datebase.models import User
from datebase.db import initialize_db
from flasgger import Swagger
from flasgger.utils import swag_from
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = uuid.uuid4().hex
app.config['MONGO_SETTINGS'] = {
    'host': "mongodb://localhost:27017/itcube"
}
app.config['JWT_EXPIRATION_DELTA'] = timedelta(days=14)
initialize_db(app)
SWAGGER_TEMPLATE = {
    "securityDefinitions": {"APIKeyHeader": {"type": "apiKey", "name": "x-access-token", "in": "header"}}}
swagger = Swagger(app, template=SWAGGER_TEMPLATE)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        if not token:
            return make_response(jsonify({'error': 'token is missing'}), 401),
        try:
            data = decode_auth_token(token)
            current_user = User.objects(public_id=data).first()
        except Exception:
            return make_response(jsonify({'error': 'token is invalid'}), 503)
        return f(current_user, *args, **kwargs)

    return decorator


def encode_auth_token(public_id):
    try:
        payload = {
            'exp': datetime.utcnow() + timedelta(days=14),
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
def index():
    return make_response('IT Cube Miass', 200)


@app.route('/register', methods=['POST'])
@swag_from('swagger/register.yml')
def register():
    if request.method == 'POST':
        body = dict()
        body['public_id'] = str(uuid.uuid4())
        body['email'] = request.json['email']
        body['password'] = generate_password_hash(request.json['password'])
        if not request.json:
            return make_response(jsonify({'error': 'Empty request'}), 400)
        elif not all(key in request.json for key in
                     ['email', 'password']):
            return make_response(jsonify({'error': 'Bad request'}), 400)
        elif User.objects(email=body['email']).first():
            return make_response(jsonify({'error': 'User already exists'}), 409)
        else:
            user = User(**body)
            user.save()
            token = encode_auth_token(user.public_id)
            return make_response(jsonify({'token': token.decode('utf-8')}), 201)


@app.route('/auth', methods=['POST'])
@swag_from('swagger/auth.yml')
def auth():
    if request.method == 'POST':
        email, password = request.json['email'], request.json['password']
        if not request.json:
            return make_response(jsonify({'error': 'Empty request'}), 400)
        elif not all(key in request.json for key in
                     ['email', 'password']):
            return make_response(jsonify({'error': 'Bad request'}), 400)
        user = User.objects(email=email).first()
        if not user:
            return make_response(jsonify({'error': 'User not exists'}), 403)
        elif check_password_hash(user.password, password):
            token = encode_auth_token(user.public_id)
            return make_response(jsonify({'token': token.decode('utf-8')}), 201)
        return make_response(jsonify({'error': 'wrong password'}), 403)


@app.route('/profile', methods=['GET'])
@swag_from('swagger/profile.yml')
@token_required
def profile(current_user):
    if not current_user:
        return make_response(jsonify({'error': 'the user is not logged in'}), 402)
    return make_response(jsonify(current_user), 200)


@app.route('/users', methods=['GET'])
@swag_from('swagger/users.yml')
@token_required
def users_list(current_user):
    if not current_user:
        return make_response(jsonify({'error': 'the user is not logged in'}), 401)
    users = User.objects()
    if users:
        return make_response(jsonify(users), 200)
    else:
        return make_response(jsonify({'error': 'No users was find'}), 404)


if __name__ == '__main__':
    app.run()
