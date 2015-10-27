import re
import os
import cgi
import webapp2
import hashlib
import jinja2
import json
from google.appengine.ext import db
from google.appengine.api import memcache, users
from google.appengine.api import mail
import xsrfutil
from xsrfutil import *

jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(
        os.path.join(os.path.dirname(__file__), 'static/templates')
    ), autoescape=True
)

jinja_env.globals['xsrf_token'] = xsrfutil.xsrf_token


def hash_str(s):
        return hashlib.md5(s).hexdigest()


def make_secure_val(s):
        return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
        val = h.split('|')[0]
        if h == make_secure_val(val):
                return val
        else:
            return None


def escape_html(s):
    return cgi.escape(s, quote=True)


def valid_username(u):
    pattern = r"^[a-zA-Z0-9_-]{3,20}$"
    a = duplicate_user(u)

    if re.search(pattern, u) and a:
        return ""

    elif not a:
        return "user already exists"

    else:
        return "invalid username"


def duplicate_user(n):
    f = 1
    q = db.GqlQuery("SELECT * FROM Users WHERE name=:1", n)
    for i in q:
        if i.name == n:
            f = 0
    if f == 1:
        return True
    else:
        return False


def valid_password(p):
    pattern = "^.{3,20}$"
    if re.search(pattern, p):
        return ""
    else:
        return "invalid password"


def valid_email(m):
    pattern = r"^[\S]+@[\S]+\.[\S]+$"
    if re.search(pattern, m) or m == "":
        return ""
    else:
        return "invalid email"


def pswd_match(p, v):
    if p == v:
        return ""
    else:
        return "passwords did not match"


def get_front():
    posts = []
    key = 'top'
    con = memcache.get(key)
    if con:
        for i in con:
            posts.append(i)
        print "from memcache"
        return posts

    else:
        con = db.GqlQuery('SELECT * FROM Wiki ORDER BY created DESC')
        for i in con:
            posts.append(i)
        print "from database"
        memcache.set(key, con)
        return posts


def get_page():
    key = 'pages'
    pag = memcache.get(key)
    if pag:
        return pag
    else:
        pag = Pages.all().order('-created')
        memcache.set(key, pag)
    return pag


class Wiki(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True, )


class Pages(db.Model):
    subject = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class PageContent(db.Model):
    content = db.TextProperty(required=True)
    subject_key = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Users(db.Model):
    name = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class Signup(Handler):

    def get(self, username="", error="", password="", erro="", verify="", err="", email="",er=""):
        self.render('signup.html', username=escape_html(username), error=error,
                    password=escape_html(password), erro=erro,
                    verify=escape_html(verify), err=err,
                    email=escape_html(email), er=er)

    def post(self):
        params = json.loads(self.request.body)
        uname = params.get('username')
        pswd = params.get('password')
        vpswd = params.get('repeat')
        mail = params.get('email')

        name = valid_username(uname)
        pwd = valid_password(pswd)
        mil = valid_email(mail)
        match = pswd_match(pswd, vpswd)
        if match == "passwords did not match":
            pwd = ""
            pswd = ""
            vpswd = ""

        if (name == "invalid username" or pwd == "invalid password" or name == "user already exists" or
                    match == "passwords did not match" or mil == "invalid email"):
            return None
        else:
            u = Users(name=uname, password=pswd, email=mail)
            u.put()
            u_name = make_secure_val(u.name)
            self.response.headers.add_header('Set-cookie', 'username=%s; Path=/'%str(u_name))
            self.redirect('/')


class Login(Handler):

    def get(self, username='', password='', error_u='', error_p=''):
        self.render('login.html', username=escape_html(username), password=escape_html(password),
                    error_u=error_u, error_p=error_p)

    def post(self):
        params = json.loads(self.request.body)
        username = params.get('username')
        password = params.get('password')
        log_check = Users.all().filter('name =', username)
        if log_check.count() > 0:
            for i in log_check.run(limit=1):
                if i.name == username and i.password == password:
                    login_cookie = make_secure_val(i.name)
                    self.response.headers.add_header('Set-cookie', 'username=%s; Path=/' % str(login_cookie))
                    self.redirect('/')
                elif username == i.name and password != i.password:
                    self.render('login.html', username=escape_html(username),
                                password='', error_u="", error_p="wrong password")
        else:
            return None


class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-cookie', 'username=%s; Path=/' % '')
        self.redirect('/')


class Mainpage(Handler):

    def get(self):
        print 'coming here'
        q = self.request.get('v')
        print q
        posts = get_front()
        pag = get_page()
        username = self.request.cookies.get("username")

        if username:
            u_name = check_secure_val(username)
            print u_name
            if u_name:
                if posts:
                    print 'in '
                    self.render('root.html', username=u_name, content=posts[0].content, page=pag)

                else:
                    print 'else in'
                    self.render('root.html', username=u_name, page=pag)

            else:
                self.redirect('/login')
        elif posts and not username:
            self.render('root.html', content=posts[0].content, page=pag)

        else:
            self.render('root.html', page=pag)


class EditPage(Handler):

    def get(self, sub):
        q = self.request.get('v')
        username = self.request.cookies.get("username")
        current_user = check_secure_val(username)
        if username and check_secure_val(username):
            print sub

            if q and not sub:
                print type(q)
                history = get_front()
                l = len(history)
                cont = history[l-int(q)].content
                print cont
                self.render('edit.html', content=cont, username=current_user)

            elif q and sub:
                print sub
                history = PageContent.all().filter('subject_key =', sub).order('-created')
                pags = []
                for i in history:
                    pags.append(i)
                l = len(pags)
                print pags
                print l
                cont = pags[l-int(q)].content
                print cont
                self.render('edit.html', content=cont, len=l, username=current_user)

            else:
                self.render('edit.html', username=current_user)

        else:
            self.redirect('/')

    def post(self, sub):
        con = self.request.get('content')
        if con:
            if not sub:
                w = Wiki(content=con)
                w.put()
                memcache.add('top', w)

                c = memcache.get('top')
                for i in c:
                    print i.content
                self.redirect('/')
            else:
                subj = Pages.all().filter('subject =', sub).get()
                if not subj:
                    s = Pages(subject=sub)
                    s.put()
                    p = PageContent(content=con, subject_key=sub)
                    p.put()
                    self.redirect('/'+sub)

                else:
                    p = PageContent(content=con, subject_key=sub)
                    p.put()
                    self.redirect('/'+sub)
        else:
            self.render('edit.html')


class NewPost(Handler):
    def get(self, a):
        page = Pages.all().filter('subject =', a).order('-created').get()
        q = self.request.get('v')
        print "value of q"
        print q
        print page
        if page is not None and q == '':

            table = PageContent.all().filter('subject_key =', a).order('-created').fetch(1)
            l = len(table)
            self.render('pages.html', subject=page.subject, content=table[0].content, history=table, len=l)

        elif page is not None and q:
            table = list(PageContent.all().filter('subject_key =', a).order('-created'))
            l= len(table)
            cont = table[l-int(q)].content
            self.render('pages.html', subject=a, content=cont)

        else:
            print "i am here"
            self.redirect('/_edit/'+a)


class History(Handler):
    def get(self, sub):

        if not sub:
            history = get_front()
            l = len(history)
            self.render('history.html', history=history, len=l)

        else:
            print sub
            table = PageContent.all().filter('subject_key =', sub).order('-created')
            pags = []
            for i in table:
                pags.append(i)

            l = len(pags)
            self.render('history.html', history=pags, len=l, sub=sub)

class mailHandler(Handler):
    def get(self):
        self.render('mail.html')

    def post(self):
        to = self.request.get('to')
        subject = self.request.get('subject')
        content = self.request.get('body')
        print to, subject, content
        message = mail.EmailMessage(sender="Manjunath Satyamurthy<pass2rahul@gmail.com>",
                            subject=subject)
        message.to = to
        message.body = content
        message.send()


class Settings(Handler):

    def get(self):
        username = self.request.cookies.get("username")
        user = check_secure_val(username)
        self.render('settings.html', username=user)

    @xsrfutil.xsrf_protect
    def post(self):
        new_password = self.request.get('new_password')
        username = self.request.cookies.get("username")
        user = check_secure_val(username)
        user_obj = Users.all().filter('name =', user).get()
        user_obj.password = new_password
        user_obj.put()
        self.redirect('/')


PAGE_RE = r'((?:[a-zA-Z0-9_-]+/?)*)'
application = webapp2.WSGIApplication(
    [('/signup', Signup),('/login', Login), ('/mail', mailHandler),\
    ('/logout', Logout), ('/', Mainpage),('/settings', Settings), \
    ('/_edit/?'+PAGE_RE, EditPage), ('/_history/?'+PAGE_RE , History), \
    ('/'+PAGE_RE, NewPost)],debug=True)