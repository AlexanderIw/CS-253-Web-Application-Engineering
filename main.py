#!/usr/bin/env python
#|//-----Lonique Alexander--------------//
#|//-----Application studies------------//
import webapp2
import cgi
import re
import os
import jinja2
import hashlib
import hmac
import random
import string
import urllib2
import json
from xml.dom import minidom
from google.appengine.ext import db

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

#variables
SECRET='itisover9000'
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
Password_RE = re.compile(r"^.{3,20}$")
Email_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

#database stuff
class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty()
    
class BlogPost(db.Model):
    subject= db.StringProperty(required=True)
    content= db.TextProperty(required =True)
    created= db.DateTimeProperty(auto_now_add = True)

class User(db.Model):
    name= db.StringProperty(required=True)
    password= db.StringProperty(required=True)
    email= db.StringProperty(required=False)
    created= db.DateTimeProperty(auto_now_add = True)

#password stuff
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt=h.split(",")[1]
    return make_pw_hash(name,pw,salt)==h
       
    
#cookies stuff
def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
        return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
        val = h.split('|')[0]
        if h == make_secure_val(val):
                return val
#project 2
def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return Password_RE.match(password)

def valid_email(email):
    return Email_RE.match(email)

def isMatch(s1,s2):
    if s1==s2:
        return "equal"

#AsciiChan 2, may put someloging in here to find errors
GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
IP_URL  = "http://api.hostip.info/?ip="
def get_coords(ip):
    ip = "96.232.236.184"
    url = IP_URL + ip
    content = None
    try:
        content = urllib2.urlopen(url).read()
    except urllib2.URLError:
        return
    if content:
        d = minidom.parseString(content)
        coords = d.getElementsByTagName("gml:coordinates")
    if coords and coords[0].childNodes[0].nodeValue:
        lon, lat = coords[0].childNodes[0].nodeValue.split(',')
        return db.GeoPt(lat, lon)

def gmaps_img(points):
    url_extention='&'.join('markers=%s,%s' % (p.lat, p.lon) for p in points)
    return (GMAPS_URL+url_extention)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_environment.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainHandler(Handler):
    def render_front(self, title="", art="", error=""):
        arts=db.GqlQuery("SELECT * FROM Art ORDER BY created desc LIMIT 10")
        #self.render("index.html", title=title, art=art, error = error, arts =arts)

        arts=list(arts)
        points = []
        for a in arts:
            if a.coords:
                points.append(a.coords)
                
        img_url = None
        if points:
            img_url = gmaps_img(points)

        self.render("index.html",  title = title, art = art, error = error, arts = arts, img_url = img_url)

    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visit_cookie_str = self.request.cookies.get('visits')

        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)
        
        visits = int(visits)+1
        new_cookie_val= make_secure_val(str(visits))

        self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)
        self.write("You've been here %s times!" % visits)
        self.write(repr(get_coords(self.request.remote_addr)))
        self.render_front()
        
    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")

        if title and art:
            a = Art(title = title, art = art)
            coords = get_coords(self.request.remote_addr)
            #if we have coordinates, add them to the art
            if coords:
                a.coords = coords
            a.put()
            self.redirect("/")
        else:
            error = "we need both a title and some artwork!"
            self.render_front(title, art,error)

#Project 3, 4, and 5
class BlogHandler(Handler):
    def render_blog(self, subject="", content=""):
        blogposts= db.GqlQuery("SELECT * FROM BlogPost ORDER BY created desc LIMIT 0, 10")
        blogposts= list(blogposts)
        self.render("blog.html", subject=subject, content=content, blogposts =blogposts)

    def get(self):
        self.render_blog()

class JsonHandler(Handler):
    def get(self):
        self.response.headers['Content-Type']='application/json; charset-UTF-8'
        blogposts= db.GqlQuery("SELECT * FROM BlogPost ORDER BY created desc LIMIT 0, 10")
        mylist=[]
        for post in blogposts:
            mylist.append({'content':post.content, 'subject':post.subject})

        self.write( json.dumps(mylist))

class PermaJsonHandler(Handler):
    def render_thepost(self, subject="", content="", post_id=""):
        blogpost= BlogPost.get_by_id(int(post_id))
        self.write(json.dumps({'content':blogpost.content,'subject':blogpost.subject}))
        
    def get(self, post_id):
        self.response.headers['Content-Type']='application/json; charset-UTF-8'
        self.render_thepost(post_id=post_id)

class NewPostHandler(Handler):
    def render_newpost(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error=error)

    def get(self):
        self.render_newpost()
        
    def post(self):
        subject= self.request.get("subject")
        content= self.request.get("content")

        if subject and content:
            temp = BlogPost(subject=subject,content= content) 
            bkey=temp.put()
            self.redirect("/blog/%s" % bkey.id())
        else:
            error="we need both subject and content"
            self.render_newpost(subject,content, error)

class PermalinkHandler(Handler):
    def render_apost(self, subject="", content="", post_id=""):
        blogpost= BlogPost.get_by_id(int(post_id))
        self.render("apost.html", subject=subject, content=content, blogpost =blogpost)
        
    def get(self, post_id):
        self.render_apost(post_id=post_id)

class SignUp(Handler):
    def render_signup(self,params=""):
        self.render("signup.html", **params)

    def get(self):
        self.render("signup.html")

    def post(self):
        #fetching the parameter out the request!!
        have_error=False
        username= self.request.get('username')
        pword= self.request.get('password')
        vword= self.request.get('verify')
        email= self.request.get('email')
     
        #dictionary
        params=dict(username=username, email=email)

        if not valid_username(username):
            params['error1']="That's not a valid user name"
            have_error=True
        if not valid_password(pword):
            params['error2']="That's not a valid password"
            have_error=True
        if not isMatch(pword,vword):
            params['error3']="The two password dont match"
            have_error=True
            if valid_password(vword):
                params['error3']=""
                params['error2']="That's not a valid password"
                have_error=True
        if email:
            if not valid_email(email):
                params['error4']="That's not a valid email"
                have_error=True

        if not have_error:
            user= User.all().filter('name =', username).get()
            if user:
                params['error1']="user already exist"
                have_error=True
            else:
                hash_pword=make_pw_hash(username, pword)
                newuser = User(name=username,password= hash_pword,email=email)
                user_id=newuser.put().id()
                new_cookie_val=make_secure_val(str(user_id))
                self.response.headers.add_header('Set-Cookie','name=%s;Path=/' % new_cookie_val)
                self.redirect("/blog/welcome")

        if have_error:
            self.render_signup(params)

class Login(Handler):
    def render_login(self,error=""):
        self.render("login.html",error=error)
    
    def get(self):
        self.render_login()
        
    def post(self):
        isError=False
        error="Invalid login, please try again"
        uname= self.request.get('username')
        pword= self.request.get('password')

        if not valid_username(uname) and  not valid_password(pword):
            isError=True

        if not isError:
            user= User.all().filter('name =', uname).get()
            if user:
                if valid_pw(uname,pword, user.password):
                    new_cookie_val=make_secure_val(str(user.key().id()))
                    self.response.headers.add_header('Set-Cookie','name=%s;Path=/' % new_cookie_val)
                    self.redirect("/blog/welcome")
            isError=True
        
        if isError:
            self.render_login(error)

class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie','name=;Path=/')
        self.redirect("/blog/signup")
    
class Welcome(Handler):
    def get(self):
        cookie_val= self.request.cookies.get('name')
        user_id=check_secure_val(cookie_val)
        if cookie_val and user_id:
            user= User.get_by_id(int(user_id))
            self.render("welcome.html",username=user.name)
        else:
            self.redirect('/blog/signup')
    
app = webapp2.WSGIApplication([('/', MainHandler),
                               ('/blog', BlogHandler),
                               ('/blog/newpost', NewPostHandler),
                               ('/blog/(\d+)', PermalinkHandler),
                               ('/blog/signup', SignUp),
                               ('/blog/welcome', Welcome),
                               ('/blog/login',Login),
                               ('/blog/logout',Logout),
                               ('/blog/.json',JsonHandler),
                               ('/blog/(\d+).json', PermaJsonHandler)],debug=True)
