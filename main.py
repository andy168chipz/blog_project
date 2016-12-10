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
import datastore
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
SECRET = 'imsosecret'


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    # Your code here
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


class signup(Handler):

    def valid_username(self, username):
        return USER_RE.match(username)

    def user_name_exist(self, username):
        q = db.GqlQuery("SELECT * FROM User")
        for user in q:
            if user.user == username:
                return True
        return False

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
        return PASS_RE.match(pw)

    def valid_email(self, email):
        return EMAIL_RE.match(email)

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
            u = datastore.User.register(username, password, email)
            u.put()
            self.set_secure_cookie('id', username)
            self.redirect('/welcome')

    def initialize(self, *args, **kw):
        webapp2.RequestHandler.initialize(self, *args, **kw)
        uid = self.read_cookie('id')
        self.user = uid


class welcome(signup):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user)
        else:
            self.redirect('/signup')


class login(signup):

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        if datastore.User.login(username, password):
            print 'success'
            self.set_secure_cookie('id', username)
            self.redirect('/welcome')
        else:
            self.render('login.html', error="username or password is invalid")


class logout(signup):
    def get(self):
        self.remove_cookie('id')
        self.redirect('/signup')


class MainPage(signup):

    def get(self):
        q = db.GqlQuery("select * from Article order by created desc")
        articles = q.fetch(limit=10)
        params = {'articles': articles}
        if self.user:
            params['user'] = self.user
        for article in articles:
            print article.comments.count()
        self.render('blog.html', **params)


class NewPost(signup):

    def render_post(self, subject='', content='', error=''):
        self.render(
            'newpost.html', subject=subject, content=content,
            error=error, Title='New Post', submit_text="Submit")

    def get(self):
        if self.user:
            self.render_post()
        else:
            self.remove_cookie('id')
            self.redirect('/login')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            article = datastore.Article(
                subject=subject, content=content, author=self.user)
            article.put()
            # print article.key().id()
            self.redirect('/' + str(article.key().id()))
        else:
            error = "WE NEED BOTH SUBJECT AND CONTENT"
            self.render_post(subject, content, error)


class Blog(signup):
    def get(self, id):
        print id
        key = db.Key.from_path('Article', int(id))
        article = db.get(key)
        articles = []
        articles.append(article)
        self.render('blog.html', articles=articles, user=self.user)


class Delete(signup):
    def get(self, id, comment_id=''):
        self.render("delete.html")

    def post(self, id, comment_id=''):
        yes = self.request.get('yes')
        no = self.request.get('no')
        if no:
            self.redirect('/' + str(id))
        elif yes and comment_id:
            datastore.Comment.delete(comment_id)
        else:
            datastore.Article.delete(id)
        time.sleep(.1)
        self.redirect('/')


class Edit(signup):
    def render_post(self, subject='', content='', error=''):
        self.render(
            'newpost.html', subject=subject,
            content=content, error=error,
            Title="Edit Post", submit_text="Save")

    def get(self, id):
        article = datastore.Article.by_id(id)
        self.render_post(subject=article.subject, content=article.content)

    def post(self, id):
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            datastore.Article.update(id, subject, content)
            self.redirect('/' + str(id))
        else:
            error = "WE NEED BOTH SUBJECT AND CONTENT"
            self.render_post(subject, content, error)


class CommentPost(signup):
    def render_comment(self, subject, text="", error=""):
        self.render('comment.html', subject=subject, text=text, error=error)

    def get(self, id, comment_id=''):
        if self.user and not comment_id:
            self.render_comment(datastore.Article.by_id(id).subject)
        else:
            self.render_comment(datastore.Article.by_id(id).subject,
                                datastore.Comment.by_id(comment_id).text)

    def post(self, id, comment_id=''):
        comment = self.request.get('comment')
        article = datastore.Article.by_id(id)
        if not comment:
            self.render_comment(article.subject,
                                error="COMMENTS CAN'T BE EMPTY")
        else:
            if not comment_id:
                c = datastore.Comment(article=article,
                                      author=self.user,
                                      text=comment)
            else:
                c = datastore.Comment.by_id(comment_id)
                c.text = comment
            c.put()
            time.sleep(.1)
            self.redirect('/')


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/signup', signup),
    ('/welcome', welcome),
    ('/login', login),
    ('/logout', logout),
    ('/newpost', NewPost),
    ('/(\d+)', Blog),
    ('/edit/(\d+)', Edit),
    ('/delete/(\d+)', Delete),
    ('/delete/(\d+)/(\d+)', Delete),
    ('/comment/(\d+)', CommentPost),
    ('/comment/(\d+)/(\d+)', CommentPost)
], debug=True)
