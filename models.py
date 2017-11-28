from CTFd.models import db

class challengeDNSConfig(db.Model):
    option = db.Column(db.Text, primary_key=True)
    value = db.Column(db.Text)

    def __init__(self, option, value):
        self.option = option
        self.value = value
