#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
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
#
import webapp2
import jinja2
import os
import datetime
import re
import random
import hashlib
import string
import json
import time
import logging
from google.appengine.ext import db
from google.appengine.api import memcache


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

SECRET = 'asdf'

#
#Entities
#
class Entry(db.Model):
    title = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    datetime = db.DateTimeProperty()

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.EmailProperty()
    datecreated = db.DateProperty(auto_now_add = True)
    lastactive = db.DateTimeProperty(auto_now_add = True)

#
#SignUp Form Verification Functions
#
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASS_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

#
#Hashing/Verification Functions
#
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))
  
def hash_password(username, password, salt = None):
    if not salt:
        salt = make_salt()
    hashed = hashlib.sha256(username + password + salt).hexdigest()
    return str.format('{0},{1}', hashed, salt)

def check_password(username, password, hashed):
    passedhash, passedsalt = hashed.split(",")
    checkhash = hash_password(username, password, salt = passedsalt)
    newhash = checkhash.split(",")[0]
    if newhash == passedhash:
        return True
    else:
        return False
#
#Database Queries/Caching
#

def recent_posts(update = False):
    key = 'recent'
    entries = memcache.get(key)
    if entries is None or update is True:
        cursor = db.GqlQuery("SELECT * FROM Entry ORDER BY datetime desc LIMIT 10")
        logging.error("Database Query")
        entries = list(cursor.run())
        memcache.set('recent', (entries, int(time.time())))
        return entries,0
    else:
        entries,seconds = memcache.get(key)
        elapsed_time = int(time.time()) - seconds
        return entries,elapsed_time

def flush_cache():
    memcache.flush_all()

#
#Custom JSON Encoder for Handing DateTime
#

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, datetime.date):
            return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)
    
#
#Handlers
#
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class BlogHandler(Handler):
    def get(self):
        query, seconds = recent_posts()
        self.render(template='blog.html',
                    query = query,
                    seconds = seconds)

class NewPostHandler(Handler):
    def get(self):
        self.render(template='newpost.html', title="", content="", error="")

    def post(self):
        title = self.request.get("subject")
        content = self.request.get("content")
        if title and content:
            entry = Entry(title=title,
                          content=content)
            entry.datetime = datetime.datetime.now()
            entry.put()
            newid = entry.key().id()
            time.sleep(0.5)
            recent_posts(update = True)
            self.redirect('/%s' % newid)
        elif not title:
            if not content:   
                self.render(template='newpost.html', title=title, content=content,
                            error="You must have a Title and Content")
            else:
                self.render(template='newpost.html', title=title, content=content,
                        error="You must have a Title")         
        else:
            self.render(template='newpost.html', title=title, content=content,
                        error="You must have Content")

class CreatedHandler(Handler):
    def get(self, blogid):
        key = blogid
        entry = memcache.get(key)
        if not entry:
            entry = Entry.get_by_id(int(blogid))
            memcache.set(key, (entry, int(time.time())))
            self.render(template = 'created.html',
                        title = entry.title,
                        content = entry.content,
                        seconds = 0)
        else:
            entry,seconds = memcache.get(key)
            seconds = int(time.time()) - seconds
            self.render(template='created.html',
                        title=entry.title,
                        content=entry.content,
                        seconds = seconds)

class SignUpHandler(Handler):        
    def get(self):
        self.render(template = 'signup.html',
                    usererror = "",
                    passerror = "",
                    emailerror = "",
                    duplicateerror = "",
                    username = "",
                    email = "")
        
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        usererror = ""
        passerror = ""
        verifyerror = ""
        emailerror = ""
        duplicateerror = ""
        errorflag = False
        
        if not valid_username(username):
            usererror = "That is not a valid username"
            errorflag = True
        if not valid_password(password):
            passerror = "That is not a valid password"
            errorflag = True
        elif password != verify:
            verifyerror = "Your passwords do not match"
            errorflag = True
        if email:
            if not valid_email(email):
                emailerror = "That is not a valid email address"
                errorflag = True
                
        cursor = db.GqlQuery("SELECT * FROM User")
        for user in cursor:
            if user.username == username:
                duplicateerror = "User already exists"
                errorflag = True
        
        if errorflag:
            self.render(template = 'signup.html',
                        usererror = usererror,
                        passerror = passerror,
                        verifyerror = verifyerror,
                        emailerror = emailerror,
                        duplicateerror = duplicateerror,
                        username = username,
                        email = email)
        else:
            if not email:
                email = None
            hashedpassword = hash_password(username, password)
            newuser = User(username = username,
                           password = hashedpassword,
                           email = email)
            newuser.put()
            newuserid = newuser.key().id()
            hashuser = hashlib.sha256(str(newuserid) + SECRET).hexdigest()
            cookieval = str.format('{0}|{1}', newuserid, hashuser)
            self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % cookieval) 
            self.redirect('/welcome')
            
class WelcomeHandler(Handler):
    def get(self):
        cookie = self.request.cookies.get('user')
        if cookie:
            userid, verifyhash = cookie.split("|")
        else:
            self.redirect('/signup')
        if userid.isdigit():
            user = User.get_by_id(int(userid))
        if user:
            newhash = hashlib.sha256(str(userid) + SECRET).hexdigest()
            if newhash == verifyhash:
                self.render(template = 'welcome.html', username = user.username)
            else:
                self.redirect('/signup')
        else:
            self.redirect('/signup')

class LoginHandler(Handler):
    def get(self):
        self.render(template = 'login.html',
                    username = "",
                    loginerror = "")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        cursor = db.GqlQuery("SELECT * FROM User WHERE username = :username", username = username)
        user = cursor.get()
        if user:
            if check_password(username, password, user.password):
                userid = user.key().id()
                hashuser = hashlib.sha256(str(userid) + SECRET).hexdigest()
                cookieval = str.format('{0}|{1}', userid, hashuser)
                self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % cookieval) 
                self.redirect('/welcome')
            else:
                self.render(template = 'login.html',
                            username = username,
                            loginerror = "Invalid Credentials")
        else:
            self.render(template = 'login.html',
                username = username,
                loginerror = "Invalid Credentials")
        
class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user=; Path=/')
        self.redirect('/signup')

class BlogJSONHandler(BlogHandler):
    def get(self):
        cursor = db.GqlQuery("SELECT * FROM Entry ORDER BY datetime desc LIMIT 10")
        entries = []
        for entry in cursor:
            new = db.to_dict(entry)
            entries.append(new)
        self.response.headers['Content-Type'] = 'application/json'
        self.write(json.dumps(entries, cls = MyEncoder))

class PermaJSONHandler(CreatedHandler):
    def get(self, blogid):
        entry = Entry.get_by_id(int(blogid))
        entry = db.to_dict(entry)
        self.response.headers['Content-Type'] = 'application/json'
        self.write(json.dumps(entry, cls = MyEncoder))

class FlushHandler(Handler):
    def get(self):
        flush_cache()
        time.sleep(.5)
        self.redirect('/')

app = webapp2.WSGIApplication([
    ('/', BlogHandler),
    ('/newpost', NewPostHandler),
    ('/(\d+)', CreatedHandler),
    ('/signup', SignUpHandler),
    ('/welcome', WelcomeHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/.json', BlogJSONHandler),
    ('/(\d+).json', PermaJSONHandler),
    ('/flush', FlushHandler)
], debug=True)
