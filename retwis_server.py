# -*- coding: utf-8 -*- 
from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash, _app_ctx_stack, make_response, \
     redirect
from time import time
import redis as _redis
import hashlib
import sys


app = Flask(__name__)
app.debug = True

def get_rand():
    data = None
    with open("/dev/random", 'rb') as f:
        data = repr(f.read(16))
    return hashlib.md5(data).hexdigest()

def is_logged():
    logged = False
    authcookie = request.cookies.get('auth')
    if authcookie:
        r = redis_link();
        user_id = r.get('auth:%s' % authcookie)

        if user_id:
            if r.get('uid:%d:auth' % long(user_id)) == authcookie:
                logged = True
    
    if not logged:
        raise RuntimeError('User is not logged')
    return load_user_info(user_id)

def load_user_info(user_id):
    r = redis_link();
    user = {
        'id': long(user_id),
        'username': r.get('uid:%d:username' % long(user_id))
    }
    
    return user;

def redis_link():
    return _redis.StrictRedis(host='localhost', port=6379, db=1)

def validate_user(username, password, password2):
    print 'Testing fields for %s' % username
    fields = []
    fields.append(username)
    fields.append(password)
    fields.append(password2)
    if "" in fields:
        raise ValueError('Every field of the registration form is needed!')
    if password != password2:
        raise ValueError('Password and password (again) must be the same')

def user_exits(username):
    print 'User exists %s ?' % username
    if redis_link().get("username:%s:id" % username):
        raise ValueError('Sorry the selected username is already in use.')

def create_user(username, password):
    print 'Creating user %s' % username
    r = redis_link()
    user_id = long(r.incr('global:nextUserId'))
    r.set('username:%s:id' % username, user_id)
    r.set('uid:%d:username' % user_id, username)
    r.set('uid:%d:password' % user_id, password)

    auth_secret = get_rand()
    r.set('uid:%d:auth' % user_id, auth_secret)
    r.set('auth:%s' % auth_secret, user_id)

    r.sadd('global:users', user_id)
    print 'User %s created' % username
    return auth_secret

def login_user(username, password):
    print 'Login user %s' % username
    r = redis_link()
    user_id = r.get('username:%s:id' % username)
    if not user_id:
        raise RuntimeError('Wrong username or password')
    user_id = long(user_id)
    realpassword = r.get('uid:%d:password' % user_id)
    if not realpassword:
        raise RuntimeError('Wrong username or password')
    auth_secret = r.get('uid:%d:auth' % user_id)
    return auth_secret

def logout_user(user_id):
    r = redis_link()
    new_auth_secret = get_rand()
    oldauthsecret = r.get('uid:%d:auth' % user_id)
    r.set('uid:%d:auth' % user_id, new_auth_secret)
    r.set('auth:%s' % new_auth_secret, user_id)
    r.delete('auth:%s' % oldauthsecret)

def new_retwis(status, user_id):
    r = redis_link()
    post_id = long(r.incr('global:nextPostId'))
    status = status.replace('\n', '')
    post = '%d|%s|%s' % (user_id, time(), status)
    r.set('post:%d' % post_id, post)
    followers = r.smembers('uid:%d:followers' % (user_id))
    followers.add(user_id)

    for follower in followers:
        r.lpush('uid:%d:posts' % long(follower), post_id)

    r.lpush('global:timeline', post_id)
    r.ltrim('global:timeline', 0, 1000)

def elapsed(t):
    d = time() - t 
    if d < 60:
        return '%d seconds' % d
    if d < 3600:
        m = d/60
        return '%d minute %s' % (m, m > 1 and 's' or '')
    if d < 3600 * 24:
        h = d/3600
        return '%d hour %s' % (h, h > 1 and 's' or '')
    d = d/(3600*24)
    return '%d day %s' % (d, d > 1 and 's' or '')

def get_user_posts(user_id, username):
    r = redis_link()
    key = user_id == -1 and 'global:timeline' or 'uid:%d:posts' % long(user_id)
    posts = r.lrange(key, 0, 1000)

    html_posts = []
    for post in posts:
        try:
            data = r.get('post:%d' % long(post))
            id, time, status = data.split('|')
            postd = {
                'username':r.get('uid:%d:username' % long(id)),
                'status':status.decode('utf-8'),
                'elapsed':elapsed(long(float(time)))
            }
            html_posts.append(postd)
        except Exception as e:
            print sys.exc_info()

    return html_posts

def get_profile(username, my_user_id):
    r = redis_link()
    user_id = r.get('username:%s:id' % username)

    if not user_id:
        raise RuntimeError('Profile %s not exists' % username)

    user_id = long(user_id)
    profile = {'user_id':user_id}
    
    if user_id == my_user_id:
        profile['self'] = True
        return profile
    else:
        profile['self'] = False

    is_following = r.sismember('uid:%d:following' % long(user_id), long(my_user_id))

    profile = {'user_id':user_id}
    if is_following:
        profile['is_following'] = True
    else:
        profile['is_following'] = False
    return profile

def user_follow(user_id, my_user_id, op):
    r = redis_link()

    if my_user_id == user_id:
        return r.get('uid:%d:username' % long(user_id))

    user_id = long(user_id)
    my_user_id = long(my_user_id)

    if op == '1':
        r.sadd('uid:%d:followers' % my_user_id, user_id);
        r.sadd('uid:%d:following' % user_id, my_user_id);
    elif op == '0':
        r.srem('uid:%d:followers' % my_user_id, user_id);
        r.srem('uid:%d:following' % user_id, my_user_id);
    else:
        raise ValueError('Invalid operation')
    return r.get('uid:%d:username' % long(user_id))

def count_followers(user_id):
    r = redis_link()
    return r.scard('uid:%d:followers' % user_id)

def count_following(user_id):
    r = redis_link()
    return r.scard('uid:%d:following' % user_id)

def get_last_users():
    r = redis_link();
    users = r.sort('global:users', get='uid:*:username', start=0, num=10);
    return users
    
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
        followers = count_followers(int(user_info['id']))
        following = count_following(int(user_info['id']))
        return render_template('home.html', logged=True,
                                username=user_info['username'],
                                followers=followers, following=following,
                                posts=get_user_posts(user_info['id'], 
                                                     user_info['username']))
    except RuntimeError, e:
        return redirect('/')

@app.route('/timeline')
def timeline():
    user_info = None

    try:
        user_info = is_logged()
        return render_template('timeline.html', logged=True,
                               last_users=get_last_users(),
                               last_posts=get_user_posts(-1, user_info['username']))
    except RuntimeError, e:
        return redirect('/')

@app.route('/profile/<username>')
def profile(username):
    user_info = None

    try:
        user_info = is_logged()
        return render_template('profile.html', logged=True,
                                username=username,
                                profile=get_profile(username, long(user_info['id'])))

    except (RuntimeError, ValueError), e:
        return render_template('profile.html', logged=True,
                                username=username,
                                err_msg=e)

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

@app.route('/login', methods=['POST'])
def login():
    try:
        username  = request.form['username']
        password  = request.form['password']

        validate_user(username, password, password)
        auth_secret = login_user(username, password)    

        ret = make_response(redirect('/home'))
        ret.set_cookie('auth', '%s' % auth_secret)

        return ret
    except ValueError, e:    
        return render_template('register.html', err_msg = e)
    except RuntimeError, e:    
        return render_template('register.html', err_msg = e)
    except Exception, e:
        print e
        err = 'Something is very wrong!'
        return render_template('register.html', err_msg = err)

@app.route('/logout', methods=['GET'])
def logout():
    user_info = None

    try:
        user_info = is_logged()

        logout_user(user_info['id'])
        return redirect('/')

    except RuntimeError, e:
        return redirect('/')

@app.route('/follow')
def follow():
    user_info = None

    try:
        user_info = is_logged()
        username = user_follow(long(request.values['uid']),
                               long(user_info['id']),
                               request.values['f'])

        return redirect('/profile/%s' % username)
    except RuntimeError, e:
        return redirect('/')
    except ValueError, e:
        return render_template('home.html', 
                                username=user_info['username'],
                                followers='', following='', err_msg=e)   
if __name__ == "__main__":
    app.run()
