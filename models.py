from CTFd.models import db

class challengeDNSConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    option = db.Column(db.Text)
    value = db.Column(db.Text)

    def __init__(self, option, value):
        self.option = option
        self.value = value
