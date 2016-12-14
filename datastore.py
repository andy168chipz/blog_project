from google.appengine.ext import db
import util
"""
Datastore module
A module that interacts with the Google datastore
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

    @classmethod
    def get_author(cls, id):
        return cls.by_id(id).author


class Comment(db.Model):
    article = db.ReferenceProperty(Article, collection_name="comments")
    text = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def get_author(cls, id):
        comment = cls.by_id(id)
        return comment.author

    @classmethod
    def by_id(cls, id):
        return db.get(db.Key.from_path('Comment', int(id)))

    @classmethod
    def delete(cls, id):
        db.delete(cls.by_id(id))
