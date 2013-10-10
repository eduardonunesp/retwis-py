from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash, _app_ctx_stack, make_response, \
     redirect
from datetime import datetime
import redis as _redis
import hashlib


app = Flask(__name__)
app.debug = True

def get_rand():
    data = None
    with open("/dev/random", 'rb') as f:
        data = repr(f.read(16))
    close(f)
    return hashlib.md5(data).hexdigest()

def is_logged():
    authcookie = request.cookies.get('auth')
    if authcookie:
        r = redis_link();
        user_id = long(r.get('auth:%s' % authcookie))
        if user_id:
            if r.get('uid:%d:auth' % user_id) != authcookie:
                raise RuntimeError('User is not logged')
            return load_user_info(user_id)
        else:
            raise RuntimeError('User is not logged')

def load_user_info(user_id):
    r = redis_link();
    user = {
        'id': user_id,
        'username': r.get('uid:%d:username' % user_id)
    }
    
    return user;

def redis_link():
    return _redis.StrictRedis(host='localhost', port=6379, db=0)

def validate_user(username, password, password2):
    print 'Testing fields for %s' % username
    fields = []
    fields.append(username)
    fields.append(password)
    fields.append(password2)
    if "" in fields:
        raise ValueError('Every field of the registration form is needed!')

def user_exits(username):
    print 'User exists %s ?' % username
    if redis_link().get("username:%s:id" % username):
        raise ValueError('Sorry the selected username is already in use.')

def create_user(username, password):
    print 'Creating user %s' % username
    r = redis_link()
    user_id = r.incr('global:nextUserId')
    r.set('username:%s:id' % username, user_id)
    r.set('uid:%d:username' % user_id, username)
    r.set('uid:%d:password' % user_id, password)

    auth_secret = 1000
    r.set('uid:%d:auth' % user_id, auth_secret)
    r.set('auth:%d' % auth_secret, user_id)

    r.sadd('global:users', user_id)
    print 'User %s created' % username
    return auth_secret

def new_retwis(status, user_id):
    r = redis_link()
    post_id = long(r.incr('global:nextPostId'))
    status = status.replace('\n', '')
    post = '%d|%s|%s' % (user_id, datetime.now(), status)
    r.set('post:%d' % post_id, post)
    followers = r.smembers('uid:%d:followers' % (user_id))
    followers.add(post)

    for follower in followers:
        r.lpush('uid:%d:posts' % user_id, post_id)

    r.lpush('global:timeline', post_id)
    r.ltrim('global:timeline', 0, 1000)

def get_user_posts(user_id):
    r = redis_link()
    key = user_id == -1 and 'global:timeline' or 'uid:%d:posts' % long(user_id)
    posts = r.lrange(key, 0, 1000)

    html_posts = []
    for post in posts:
        try:
            data = r.get('post:%d' % int(post))
            id, time, status = data.split('|')
            post_tpl = '%s'
            html_posts.append(post_tpl % status)
        except:
            pass

    return html_posts

@app.route("/")
def root():
    try:
        user_info = is_logged()
        return redirect('/home')
    except Exception, e:
        print e
    return render_template('index.html')

@app.route("/register", methods=['POST'])
def register():
    try:
        username  = request.form['username']
        password  = request.form['password']
        password2 = request.form['password2']

        validate_user(username, password, password2)
        user_exits(username) 
        auth_secret = create_user(username, password)    
        ret = make_response(render_template('register.html',
                            username=request.form['username']))
        ret.set_cookie('auth', '%s' % auth_secret)

        return ret
    except ValueError, e:    
        return render_template('register.html', err_msg = e)
    except Exception, e:
        print e
        err = 'Something is very wrong!'
        return render_template('register.html', err_msg = err)

@app.route('/home')
def home():
    try:
        user_info = is_logged()

        return render_template('home.html', 
                                username=user_info['username'],
                                followers='', following='',
                                posts=get_user_posts(user_info['id']))    
    except RuntimeError, e:
        return redirect('/')

@app.route('/post', methods=['POST'])
def post():
    user_info = None

    try:
        user_info = is_logged()

        if not request.form['status']:
            raise ValueError('Status cannot be empty')

        new_retwis(request.form['status'], user_info['id'])
        return redirect('/home')

    except RuntimeError, e:
        return redirect('/')
    except ValueError, e:
        return render_template('home.html', 
                                username=user_info['username'],
                                followers='', following='', err_msg=e)    

if __name__ == "__main__":
    app.run()