from google.appengine.ext import db
import util

"""
This db model has information about a user
"""


class User(db.Model):
    user = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('user =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = util.make_pw_hash(name, pw)
        return User(user=name,
                    password=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        user = cls.by_name(name)
        if user:
            return util.valid_pw(name, pw, user.password)
