import uuid
from users import User

import pymongo
from werkzeug.security import generate_password_hash, check_password_hash
from flask import jsonify
client = pymongo.MongoClient("mongodb://vadim:Oxan4ikDanArt@cluster0-shard-00-00.ckxy7.mongodb.net:27017,cluster0-shard-00-01.ckxy7.mongodb.net:27017,cluster0-shard-00-02.ckxy7.mongodb.net:27017/myFirstDatabase?ssl=true&replicaSet=atlas-7snvuk-shard-0&authSource=admin&retryWrites=true&w=majority")
db = client.itcube
coll = db.users


def find_in_base(param_to_find, param_value):
        user_data = coll.find_one({param_to_find: param_value})
        return User(user_data['public_id'], user_data['email'], user_data['password'])

