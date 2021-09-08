class User:
    def __init__(self, public_id, email, password):
        self.public_id = public_id
        self.email = email
        self.password = password

    def __repr__(self):
        return f'{self.email}'
