from google.appengine.ext import db
import post
from user import User
"""
This db model has information about a comment
"""


class Comment(db.Model):
    post = db.ReferenceProperty(post.Post, collection_name="comments")
    text = db.TextProperty(required=True)
    author = db.ReferenceProperty(User, collection_name="comments")
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
