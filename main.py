# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import webapp2
import jinja2
import re
import hmac
import time
from models.comment import Comment
from models.post import Post
from models.user import User
from google.appengine.ext import db
from functools import wraps

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def hash_str(s):
    SECRET = 'imsosecret'
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    s = h.split('|')[0]
    if h == make_secure_val(s):
        return s


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class SignUpHandler(Handler):
    @classmethod
    def user_logged_in(cls, f):
        @wraps(f)
        def wrapper(self, *args, **kargs):
            if self.user:
                f(self, *args, **kargs)
            else:
                self.remove_cookie('id')
                self.redirect('/login')
        return wrapper

    @classmethod
    def not_own_post_and_not_liked(cls, f):
        @wraps(f)
        def wrapper(self, id):
            user = Post.get_author(id)
            likes = Post.get_likes(id)
            if user and user.user != self.user and self.user not in likes:
                f(self, id)
            else:
                self.render_error(
                    'You cannot like twice!'if self.user in likes
                    else 'You cannot like your own post')
        return wrapper

    @classmethod
    def user_owns_post(cls, f):
        @wraps(f)
        def wrapper(self, id):
            user = Post.get_author(id)
            if user and user.user == self.user:
                f(self, id)
            else:
                self.render_error('You don\'t own this post')
        return wrapper

    @classmethod
    def user_owns_comment(cls, f):
        @wraps(f)
        def wrapper(self, id):
            user = Comment.get_author(id)
            if user and user.user == self.user:
                f(self, id)
            else:
                self.render_error('You don\'t own this comment')
        return wrapper

    @classmethod
    def comment_exist(cls, f):
        @wraps(f)
        def wrapper(self, id):
            if Comment.by_id(id):
                f(self, id)
            else:
                self.render_error('Comment doesn\'t exist!')
        return wrapper

    @classmethod
    def post_exists(cls, f):
        '''decorator for post exist'''
        @wraps(f)
        def wrapper(self, id):
            if Post.by_id(id):
                f(self, id)
            else:
                self.render_error('Post doesn\'t exist')
        return wrapper

    def valid_username(self, username):
        user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return user_re.match(username)

    def user_name_exist(self, username):
        u = User.by_name(username)
        return u

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie', str('%s=%s; Path=/;' % (name, cookie_val)))

    def remove_cookie(self, name):
        self.response.headers.add_header(
            'Set-Cookie', str('%s=; Path=/' % name))

    def read_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def valid_password(self, pw):
        pass_re = re.compile(r"^.{3,20}$")
        return pass_re.match(pw)

    def valid_email(self, email):
        email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return email_re.match(email)

    def get(self):
        self.render('signup.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        v_password = self.request.get('verify')
        email = self.request.get('email')
        is_same_pw = password == v_password
        is_dupe = self.user_name_exist(username)

# should check for errors first, if there are errors, stay, else render welcome
        has_error = False
        params = {
            'username': username,
            'email': email
        }
        if not self.valid_username(username):
            params['username_err'] = 'User name has errors'
            has_error = True
        elif is_dupe:
            params['username_err'] = 'User exist!!!'
            has_error = True
        if not self.valid_password(password):
            params['password_err'] = 'Password invalid'
            has_error = True
        if not is_same_pw:
            params['verify_err'] = "Password didn't match"
            has_error = True
        if email and not self.valid_email(email):
            params['email'] = "Invalide email address"

        # Complete error handling, redirect
        if has_error:
            self.render('signup.html', **params)
        else:
            u = User.register(username, password, email)
            u.put()
            self.set_secure_cookie('id', username)
            self.redirect('/welcome')

    def initialize(self, *args, **kw):
        webapp2.RequestHandler.initialize(self, *args, **kw)
        uid = self.read_cookie('id')
        self.user = uid

    def render_error(self, error):
        self.render('error.html', error=error)


class welcome(SignUpHandler):
    @SignUpHandler.user_logged_in
    def get(self):
        self.render('welcome.html', username=self.user)


class login(SignUpHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        if User.login(username, password):
            self.set_secure_cookie('id', username)
            self.redirect('/welcome')
        else:
            self.render('login.html', error="username or password is invalid")


class logout(SignUpHandler):
    def get(self):
        self.remove_cookie('id')
        self.redirect('/signup')


class MainPage(SignUpHandler):
    def get(self):
        q = db.GqlQuery("select * from Post order by created desc")
        posts = q.fetch(limit=10)
        params = {'posts': posts}
        if self.user:
            params['user'] = self.user
        self.render('blog.html', **params)


class NewPost(SignUpHandler):
    def render_post(self, subject='', content='', error=''):
        self.render(
            'newpost.html', subject=subject, content=content,
            error=error, Title='New Post', submit_text="Submit")

    @SignUpHandler.user_logged_in
    def get(self):
        self.render_post()

    @SignUpHandler.user_logged_in
    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            article = Post(
                subject=subject, content=content)
            article.author = User.by_name(self.user)
            article.put()
            self.redirect('/' + str(article.key().id()))
        else:
            error = "WE NEED BOTH SUBJECT AND CONTENT"
            self.render_post(subject, content, error)


class Blog(SignUpHandler):
    def get(self, id):
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        posts = []
        posts.append(post)
        self.render('blog.html', posts=posts, user=self.user)


class Delete(SignUpHandler):
    @SignUpHandler.post_exists
    @SignUpHandler.user_owns_post
    def get(self, id):
        self.render("delete.html")

    @SignUpHandler.post_exists
    @SignUpHandler.user_owns_post
    def post(self, id):
        yes = self.request.get('yes')
        no = self.request.get('no')
        if no:
            self.redirect('/' + str(id))
        elif yes:
            Post.delete(id)
        else:
            self.render_error('There has been an error')
        time.sleep(.1)
        self.redirect('/')


class Edit(SignUpHandler):
    def render_post(self, subject='', content='', error=''):
        self.render(
            'newpost.html', subject=subject,
            content=content, error=error,
            Title="Edit Post", submit_text="Save")

    @SignUpHandler.post_exists
    @SignUpHandler.user_owns_post
    def get(self, id):
        article = Post.by_id(id)
        self.render_post(subject=article.subject, content=article.content)

    @SignUpHandler.post_exists
    @SignUpHandler.user_owns_post
    def post(self, id):
        if id and Post.get_author(id).user != self.user:
            return self.redirect('/deleteError')
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            Post.update(id, subject, content)
            self.redirect('/' + str(id))
        else:
            error = "WE NEED BOTH SUBJECT AND CONTENT"
            self.render_post(subject, content, error)


class CommentPost(SignUpHandler):
    def render_comment(self, subject, text="", error=""):
        self.render('comment.html', subject=subject, text=text, error=error)

    @SignUpHandler.post_exists
    @SignUpHandler.user_owns_post
    def get(self, id):
        self.render_comment(Post.by_id(id).subject)

    @SignUpHandler.post_exists
    @SignUpHandler.user_owns_post
    def post(self, id):
        comment = self.request.get('comment')
        article = Post.by_id(id)
        if not comment:
            self.render_comment(article.subject,
                                error="COMMENTS CAN'T BE EMPTY")
        else:
            c = Comment(article=article,
                        text=comment)
            c.author = User.by_name(self.user)
            c.post = Post.by_id(id)
            c.put()
            time.sleep(.1)
            self.redirect('/')


class DeleteComment(SignUpHandler):
    @SignUpHandler.comment_exist
    @SignUpHandler.user_owns_comment
    def get(self, id):
        self.render("delete.html")

    @SignUpHandler.comment_exist
    @SignUpHandler.user_owns_comment
    def post(self, id):
        yes = self.request.get('yes')
        no = self.request.get('no')
        if no:
            return self.redirect('/')
        elif yes:
            Comment.delete(id)
        else:
            self.render_error('There has been an error')
        time.sleep(.1)
        self.redirect('/')


class EditComment(CommentPost):
    @SignUpHandler.comment_exist
    @SignUpHandler.user_owns_comment
    def get(self, id):
        c = Comment.by_id(id)
        self.render_comment(c.post.subject, c.text)

    @SignUpHandler.comment_exist
    @SignUpHandler.user_owns_comment
    def post(self, id):
        text = self.request.get('comment')
        c = Comment.by_id(id)
        if text:
            c.text = text
            c.put()
            time.sleep(.1)
            self.redirect('/')
        else:
            self.render_comment(subject=c.subject,
                                error="Comments can't be empty")


class LikePost(SignUpHandler):
    @SignUpHandler.post_exists
    @SignUpHandler.user_logged_in
    @SignUpHandler.not_own_post_and_not_liked
    def get(self, id):
        p = Post.by_id(id)
        p.likes.append(self.user)
        p.put()
        time.sleep(.1)
        self.redirect('/')


class DeleteError(SignUpHandler):
    def get(self):
        self.render('error.html')


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/signup', SignUpHandler),
    ('/welcome', welcome),
    ('/login', login),
    ('/logout', logout),
    ('/newpost', NewPost),
    ('/(\d+)', Blog),
    ('/edit/(\d+)', Edit),
    ('/delete/(\d+)', Delete),
    ('/delete_comment/(\d+)', DeleteComment),
    ('/comment/(\d+)', CommentPost),
    ('/comment_edit/(\d+)', EditComment),
    ('/like/(\d+)', LikePost),
    ('/deleteError', DeleteError)
], debug=True)
