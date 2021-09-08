import uuid

import pymongo
from werkzeug.security import generate_password_hash, check_password_hash
from flask import jsonify
client = pymongo.MongoClient("mongodb://vadim:Oxan4ikDanArt@cluster0-shard-00-00.ckxy7.mongodb.net:27017,cluster0-shard-00-01.ckxy7.mongodb.net:27017,cluster0-shard-00-02.ckxy7.mongodb.net:27017/myFirstDatabase?ssl=true&replicaSet=atlas-7snvuk-shard-0&authSource=admin&retryWrites=true&w=majority")
db = client.itcube
coll = db.users


def add_user(email, hash, public_id):
        coll.insert_one({
                'email': email,
                'password': hash,
                'public_id': public_id})


def user_login(email, password):
        if coll.find_one({'email': email}):
                if check_password_hash(coll.find_one({'email': email})['password'], password):
                        return jsonify({'status': 'OK'})
                else:
                        return jsonify({'error': 'Invalid password'})
        else:
                return jsonify({'error': 'User does not exists'})


def user_find(find_param, param):
        return coll.find_one({find_param: param})

