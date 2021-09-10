import pymongo

client = pymongo.MongoClient("mongodb://vadim:Oxan4ikDanArt@cluster0-shard-00-00.ckxy7.mongodb.net:27017,cluster0-shard-00-01.ckxy7.mongodb.net:27017,cluster0-shard-00-02.ckxy7.mongodb.net:27017/myFirstDatabase?ssl=true&replicaSet=atlas-7snvuk-shard-0&authSource=admin&retryWrites=true&w=majority")
db = client.itcube
coll = db.users


class User:
    def __init__(self, public_id, email, password):
        self.public_id = public_id
        self.email = email
        self.password = password

    def add_to_base(self):
        coll.insert_one({
            'email': self.email,
            'password': self.password,
            'public_id': self.public_id})

    def __repr__(self):
        return f'{self.email}'
