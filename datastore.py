from google.appengine.ext import db
import random
import hmac
import string
"""
Datastore module
A module that interacts with the Google datastore
"""


def make_salt(length=5):
    return ''.join(random.choice(string.letters) for x in range(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hmac.new(salt, name + pw).hexdigest()
    return '%s|%s' % (salt, h)  # what gets store in db


def valid_pw(name, pw, h):
    salt = h.split('|')[0]  # get the salt
    return make_pw_hash(name, str(pw), str(salt)) == h


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
        pw_hash = make_pw_hash(name, pw)
        return User(user=name,
                    password=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        user = cls.by_name(name)
        if user:
            return valid_pw(name, pw, user.password)


class Article(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.StringProperty(required=True)

    @classmethod
    def by_id(cls, id):
        return db.get(db.Key.from_path('Article', int(id)))

    @classmethod
    def update(cls, id, subject, content):
        article = cls.by_id(id)
        article.subject = subject
        article.content = content
        return article.put()

    @classmethod
    def delete(cls, id):
        article = cls.by_id(id)
        db.delete(article)


class Comment(db.Model):
    article = db.ReferenceProperty(Article, collection_name="comments")
    text = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, id):
        return db.get(db.Key.from_path('Comment', int(id)))

    @classmethod
    def delete(cls, id):
        db.delete(cls.by_id(id))
