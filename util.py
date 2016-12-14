import random
import string
import hashlib


def make_salt(length=5):
    return ''.join(random.choice(string.letters) for x in range(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(salt + name + pw).hexdigest()
    return '%s|%s' % (salt, h)  # what gets store in db


def valid_pw(name, pw, h):
    salt = h.split('|')[0]  # get the salt
    return make_pw_hash(name, str(pw), str(salt)) == h
