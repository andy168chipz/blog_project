from google.appengine.ext import db
import user

"""
This db model has information about a post
"""


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.ReferenceProperty(user.User, collection_name="posts")

    @classmethod
    def by_id(cls, id):
        return db.get(db.Key.from_path('Post', int(id)))

    @classmethod
    def update(cls, id, subject, content):
        post = cls.by_id(id)
        post.subject = subject
        post.content = content
        return post.put()

    @classmethod
    def delete(cls, id):
        post = cls.by_id(id)
        db.delete(post)

    @classmethod
    def get_author(cls, id):
        return cls.by_id(id).author
