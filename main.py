import json

import webapp2
import cgi
import string
import re
import jinja2
import os
from google.appengine.ext import db
import hashlib
import hmac
import random
import urllib2


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def renderstr(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)



class Base(webapp2.RequestHandler):
    
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        self.response.out.write(renderstr(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/'%(name, cookie_val))
    
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
    
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith(".json"):
            self.format = 'json'
        else:
            self.format = 'html'

# Main webpage handler.
class MainHandler(Base):
    def get(self): 
        self.render('frontpage.html', intro_text = "hello")

#Homework 2
class Rot13Handler(Base):
    def get(self):
        self.render("rot13form.html", text = "rot13")
    def post(self):
        user_text = self.request.get('text')
        new_text = rot13word(user_text)
        self.render("rot13form.html", text = new_text)

def rot13(c):
        if c.isupper():
            start = ord('A')
        else:
            start = ord('a')
        c_ord = ord(c)
        temp_ord = c_ord -start
        final_ord = ((temp_ord+13)%26)+start
        return chr(final_ord)

def rot13word(word):
    new_word = ''
    for c in word:
        if c not in string.punctuation and c not in string.whitespace and c not in string.digits:
            new_word = new_word + rot13(c)
        else: 
            new_word = new_word + c
    return new_word



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_UN(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_pass(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class SignUpHandler(Base):
    def get(self):
        self.render("signup.html")

    def post(self):
        Err = False
        self.username = self.request.get("username")
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username, email = self.email)

        if not valid_UN(self.username):
            params["error_username"] = "That username is not valid"
            Err = True

        if not valid_pass(self.password):
            params["error_password"] = "That password is not valid"
            Err = True

        elif not self.password == self.verify:
            params["error_verify"] = "Those passwords don't match"
            Err = True

        if not valid_email(self.email):
            params["error_email"] = "That E-mail is not valid"
            Err = True

        if Err == True:
            self.render("signup.html", **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class HW2Signup(SignUpHandler):
    def done(self):
        self.redirect('/hw2/signup/welcome?username='+self.username)

class Post(db.Model):
    subject = db.StringProperty(required = True) # Can't make a database entity Blogpost without a subject
    content = db.TextProperty(required = True)
    date_submitted = db.DateTimeProperty(auto_now_add = True)
   
    def dict(self):
        d = {'content':self.content,'subject':self.subject,'date_submitted':self.date_submitted.strftime('%c')}
        return d

class Blog(Base):
    def get(self):
        j= []
        posts = db.GqlQuery("SELECT * FROM Post" " ORDER BY date_submitted DESC LIMIT 10")
        if self.format =='html':
            self.render("front.html", posts = posts)
        else:
            j = []
            for post in posts:
                j.append(post.dict())
                json_text = json.dumps(j)
                self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
            self.write(json_text)

class NewPostHandler(Base):
    def render_blog(self, subject="", content = "", error=""):
        self.render("blog.html", subject = subject, content = content, error = error)

    def get(self):
        self.render_blog()

    def post(self):
        content = self.request.get("content")
        subject = self.request.get("subject")
        if subject and content:
            a = Post(subject =subject, content = content)
            a.put()
            self.redirect("/blog/posts/%s"% str(a.key().id()))
        else:
            error = "Please submit both a subject and content"
            self.render("blog.html", subject = subject, content = content, error = error)

class Permalink(Base):
    def get(self,post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        if not post:
            self.error(404)
            return
        if self.format == 'html':
            self.render("permlink.html", post = post)
        else:
            json_text = json.dumps(post.dict())
            self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
            self.write(json_text)


SECRET = 'kobebryanttop5alltime'

def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" %(s, hash_str(s))

def check_secure_val(h):
    s = h.split('|')[0]
    if h == make_secure_val(s):
        return s

def make_salt(length = 5):
    salt = []
    for x in xrange(length):
        salt.append(random.choice(string.letters))
        s = ''.join(salt)
        return s

def make_pw_hash(name, pw, salt = make_salt(5)):
    h = hashlib.sha256(name+pw+salt).hexdigest()
    return '%s|%s' % (salt, h)

def valid_pw(name, pw, h):
    salt = h.split('|')[0]
    if h == make_pw_hash(name, pw, salt):
        return True

def users_key(group = 'default'):
    return db.Key.from_path('users',group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod   #decorator: you can call this method on this object. 
    def by_id (cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name (cls, name):
        u =  User.all().filter('name =',name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)


class Register(SignUpHandler):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render("signup.html", error_user_exists = msg)
        else: 
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.set_secure_cookie('user_id',str(u.key().id()))
            self.redirect('/blog/welcome')

class Login(Base):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        
        u = User.by_name(username)
        if u and valid_pw(username, password, u.pw_hash):
            self.set_secure_cookie('user_id',str(u.key().id()))
            self.redirect('/blog/welcome')
        else: 
            msg = "That username and password combination is not valid."
            self.render('login.html', invalid_login = msg)

class Logout(Base):
    def get(self):
        self.request.cookies.get('user_id')
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/'%('user_id',''))
        self.redirect('/blog/signup')

class HW2Welcome(Base):
    def get(self):
        username = self.request.get('username')
        # self.render('welcome.html', username = username)
        if valid_UN(username):
            self.render('welcome.html',username = username)
        else:
            self.redirect('/hw2/signup')

class HW4Welcome(Base):
     def get(self):
        if(self.user):
            self.render('welcome.html',username = self.user.name)
        else:
            self.redirect('/hw4/signup')







app = webapp2.WSGIApplication([('/', MainHandler),
                               ('/hw2/rot13', Rot13Handler),
                               ('/hw2/signup', HW2Signup),
                               ('/hw2/signup/welcome', HW2Welcome),
                               ('/blog/welcome', HW4Welcome),
                               ('/blog/signup', Register),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/?(?:\.json)?', Blog),
                               ('/blog/newpost', NewPostHandler),
                               ('/blog/posts/([0-9]+)(?:\.json)?', Permalink)
                               ], 
								debug=True)