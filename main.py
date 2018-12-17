from flask import Flask, request, jsonify
from flask_mail import Mail, Message
import mysql_handler as localsql
import re, bcrypt, datetime, json, random
from random import randint
from pathlib import Path

# basic Flask setup
app = Flask(__name__)

# basic Flask mail setup
app.config.update(
	MAIL_SERVER = 'localhost',
	MAIL_PORT = 290,
	MAIL_USE_TLS = False,
	MAIL_USE_SSL = True,
    MAIL_USERNAME = "email-verification@tutorialpaths.com",
    MAIL_PASSWORD = Path('../priv/mail-tp-pass.txt').read_text()
)
mail = Mail(app)

# basic functions
def loadFile(url):
    try:
        html = open(url, "r")
        return html.read()
    except Exception as e:
        return None

def strDateToPython(date):
    return datetime.strptime(date, '%Y-%m-%dT%H:%M:%S.%fZ')

def pythonToStrDate(d):
    return json.dumps(d.isoformat())

# testing
@app.route('/<path:path>', methods=["GET"])
def home(path):
    return "This is the TutorialPaths gateway, where the web application interacts with the server."

@app.route('/', methods=["GET"])
def homea():
    return "This is the TutorialPaths gateway, where the web application interacts with the server."

@app.route('/v1/autho/login', methods=["POST"])
def v1authologin():
    email = ""
    password = ""
    try:
        data = request.get_json(force=True)
        email = data['username']
        password = data['password']
    except Exception as e:
        abort(400)
    
    user = None
    
    res = localsql.fetchone("SELECT * FROM users WHERE email = %s", email)
    if res['success']:
        if res['results']:
            user = res
            dbpassword = res['results'][3]
            if not bcrypt.checkpw(password.encode(), dbpassword.encode()):
                return '{"code": "AUTH/L/P0", "description": "incorrect-password"}'
        else:

            res = localsql.fetchone("SELECT * FROM users WHERE `u:id` = %s", email)
            if res['success']:
                if res['results']:
                    user = res
                    dbpassword = res['results'][3]
                    if not bcrypt.checkpw(password.encode(), dbpassword.encode()):
                        return '{"code": "AUTH/L/P0", "description": "incorrect-password"}'
                else:
                    return '{"code": "AUTH/L/U0", "description": "user-not-found"}'
            else:
                return '{"code": "DB/gen", "description": "database-transaction-error"}'

    else:
        return '{"code": "DB/gen", "description": "database-transaction-error"}'
    
    
    # fun session stuff
    sessionid = ''
    while sessionid == '':
        sessionid = 'sr:' + ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for n in range(40)])
        res = localsql.fetchone("SELECT * FROM sessions WHERE 'sr:id' = %s", sessionid)
        if res['success']:
            if res['results']:
                sessionid = ''
        else:
            return '{"code": "DB/gen", "description": "database-transaction-error"}'
    
    res = localsql.execute("INSERT INTO sessions (`ur:id`, `sr:id`, ip, creation, expiry) VALUES (%s, %s, %s, %s, %s)", True, False, user['results'][0], sessionid, request.remote_addr,  pythonToStrDate(datetime.datetime.now()), pythonToStrDate(datetime.datetime.now() + datetime.timedelta(days=1)))
    
    if res['success']:
        return '{"success": true, "session": "' + sessionid + '"}'
    else:
        return '{"code": "DB/gen", "description": "database-transaction-error"}'

@app.route('/v1/autho/register/first', methods=["POST"])
def v1authoregisterfirst():
    email = ""
    try:
        data = request.get_json(force=True)
        email = data['email']
    except Exception as e:
        abort(400)
    
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return '{"code": "AUTH/R1/E0", "description": "email-not-valid"}'
    
    res = localsql.fetchone("SELECT * FROM users WHERE email = %s", email)
    if res['success']:
        if res['results']:
            return '{"code": "AUTH/R1/E1", "description": "email-in-use"}'
    else:
        return '{"code": "DB/gen", "description": "database-transaction-error"}'
    
    code = str(randint(100000, 999999))
    resend = False
    
    res = localsql.fetchone("SELECT * FROM users_verification WHERE email = %s", email)
    if res['success']:
        if res['results']:
            code = res['results'][1]
            resend = True
    
    if resend is False:
        res = localsql.execute("INSERT INTO users_verification (email, code) VALUES (%s, %s)", True, False, email, code)
        if not res['success']:
            return '{"code": "DB/gen", "description": "database-transaction-error"}'
    
    msg = Message(subject='Code: {}'.format(code), sender=("Email Verification", "email-verification@tutorialpaths.com"), recipients = [email])
    
    msg.body = "We just need to verify your email address to finish signing you up. To make it as easy as possible, we put the code in the subject so you didn't even need to read this!\nIf you're reading it anyway, your code is {verif_code}.\n\nYou can't unsubscribe from these emails.".format(verif_code=code)
    html = loadFile('files/email_templates/verify.html')
    msg.html = html.format(verif_code=code)
    mail.send(msg)

    return '{"success": true}'

@app.route('/v1/autho/register/second', methods=["POST"])
def v1authoregistersecond():
    try:
        code = ""
        username = ""
        email = ""
        password = ""
        try:
            data = request.get_json(force=True)
            code = str(data['code1']) + str(data['code2']) + str(data['code3']) + str(data['code4']) + str(data['code5']) + str(data['code6'])
            username = data['username']
            email = data['email']
            password = data['confpassword']
        except Exception as e:
            abort(400)
        
        # first, check the code
        res = localsql.fetchone("SELECT * FROM users_verification WHERE email = %s", email)
        if res['success']:
            if res['results'][1] != code:
                return '{"code": "AUTH/R2/C1", "description": "code-invalid"}'
        else:
            return '{"code": "DB/gen", "description": "database-transaction-error", "loc": "7"}'
                
        res = localsql.fetchone("SELECT * FROM users WHERE username = %s", username)
        if res['success']:
            if res['results']:
                return '{"code": "AUTH/R2/U1", "description": "username-in-use"}'
        else:
            return '{"code": "DB/gen", "description": "database-transaction-error", "loc": "8"}'
                        
        if len(password) < 8:
            return '{"code": "AUTH/R2/P1", "description": "weak-password"}'
                        
    
        password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                        
        randomuid = ''
        while randomuid == '':
            randomuid = 'ur:' + ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for n in range(20)])
            res = localsql.fetchone("SELECT * FROM users WHERE `ur:id` = %s", randomuid)
            if res['success']:
                if res['results']:
                    randomuid = ''
            else:
                return '{"code": "DB/gen", "description": "database-transaction-error", "loc": "9"}'
        
        res = localsql.execute("INSERT INTO users (`ur:id`, username, email, password) VALUES (%s, %s, %s, %s); INSERT INTO users_public (`ur:id`, avatar, credits, creation) VALUES (%s, %s, %s, %s); INSERT INTO users_private (`ur:id`, preferences) VALUES (%s, %s)", True, True, randomuid, username, email, password, randomuid, 'DEFAULT', 1, datetime.datetime.now().isoformat(), randomuid, '{}')
        if res['success']:
            return '{"success": true}'
        else:
            return '{"code": "DB/gen", "description": "database-transaction-error", "loc": "' + res['error'] + '"}'
        
        res = localsql.execute("INSERT INTO users (`ur:id`, username, email, password) VALUES (%s, %s, %s, %s)", True, False, randomuid, username, email, password)
        if res['success']:
            res = localsql.execute("INSERT INTO users_public (`ur:id`, avatar, credits, creation) VALUES (%s, %s, %s, %s)", True, False, randomuid, 'DEFAULT', 1, pythonToStrDate(datetime.datetime.now()))
            if res['success']:
                res = localsql.execute("INSERT INTO users_private (`ur:id`, preferences) VALUES (%s, %s)", True, False, randomuid, '{}')
                if res['success']:
                    return '{"success": true}'
                else:
                    ret = localsql.execute("DELETE FROM users WHERE 'ur:id' = %s", True, False, randomuid)
                    reta = localsql.execute("DELETE FROM users_public WHERE 'ur:id' = %s", True, False, randomuid)
                    
                    if ret['success'] and reta['success']:
                        return '{"code": "DB/gen", "description": "database-transaction-error", "loc": "' + res['error'] + '"}'
                    else:
                        msg = Message(subject='DATABASE BROKE', sender=("Email Verification", "email-verification@tutorialpaths.com"), recipients = ['lachlan.walls1@gmail.com'])
                        msg.body = "AHHH SOMEONE BROKE THE TUTORIALPATHS DATABSE! PLZ SEND HELP!"
                        mail.send(msg)
                        return '{"code": "DB/manualclean", "description": "database-broken"}'
            else:
                ret = localsql.execute("DELETE FROM users WHERE 'ur:id' = %s", True, False, randomuid)
                if ret['success']:
                    return '{"code": "DB/gen", "description": "database-transaction-error", "loc": "' + res['error'] + '"}'
                else:
                    return '{"code": "DB/manualclean", "description": "database-broken"}'
        else:
            return '{"code": "DB/gen", "description": "database-transaction-error", "loc": "' + res['error'] + '"}'
        
    except Exception as e:
        return str(e)


@app.route('/v1/loader/tutorials/<method>', methods=["POST"])
def v1loadertutorialsmethod(method):
    if method == 'best':
        res = localsql.fetchall("SELECT * FROM tutorials")
        if res['success']:
            if res['results']:
                json = "["
                for result in res['results']:
                    tags = '['
                    ret = localsql.fetchall("SELECT * FROM tags_tutorials WHERE `tr:id` = %s", result[0])
                    if ret['success']:
                        if ret['success']:
                            for reso in ret['results']:
                                if ret['results'].index(reso):
                                    tags += ", "
                                tags += '"' + reso[0] + '"'
                        tags += ']'
                    else:
                        return '{"code": "DB/gen", "description": "database-transaction-error", "loc": "' + res['error'] + '"}'
                    if res['results'].index(result):
                        json += ", "
                    json += '{{"title": "{}", "tags": {}, "description": "{}", "support": {}, "rating": {}, "image": "{}", "url": "{}", "start": "{}"}}'.format(result[3], tags, result[4], '["support", "not", "set", "up"]', 1 - (result[6] / result[5]), result[7], "https://tutorialpaths.com/" + result[1].replace(':', '/'), "https://tutorialpaths.com/" + result[1].replace(':', '/'))
                json += "]"
                return json
            else:
                return "[]"
        else:
            return '{"code": "DB/gen", "description": "database-transaction-error", "loc": "' + res['error'] + '"}'
    else:
        return '{"code": "LOADER/TUTS/01", "description": "method-not-recognised"}'


@app.route('/v1/loader/tutorial/<id>', methods=["POST"])
def v1loadertutorialid(id):
    try:
        res = localsql.fetchone("SELECT * FROM tutorials WHERE `t:id` = %s", "t:" + id)
        if res['success']:
            if res['results']:
                result = res['results']
                
                res = localsql.fetchall("SELECT * FROM tutorials_steps WHERE `tr:id` = %s", result[0])
                if res['success']:
                    
                    steps = '['
                    if res['results']:
                        for reso in res['results']:
                            if res['results'].index(reso):
                                steps += ", "
                            steps += '{{"sr:id": "{}", "s:id": "{}", "author": "{}", "title": "{}", "content": "{}", "type": "{}"}}'.format(reso[1], reso[2], reso[3], reso[4], reso[5].replace("\n", "<br>"), reso[6])
                    steps += ']'
                    
                else:
                    return '{"code": "DB/gen", "description": "database-transaction-error", "loc": "' + res['error'] + '"}'
                
                res = localsql.fetchall("SELECT * FROM tutorials_branches WHERE `tr:id` = %s", result[0])
                if res['success']:
                    
                    branches = '['
                    if res['results']:
                        for reso in res['results']:
                            if res['results'].index(reso):
                                branches += ", "
                            branches += '{{"br:id": "{}", "type": "{}", "title": "{}", "content": "{}", "author": "{}", "pull_sr:id": "{}", "push_tr:id": "{}", "push_sr:id": "{}", "throw_sr:id": "{}"}}'.format(reso[1], reso[2], reso[3], reso[4], reso[5], reso[6], reso[7], reso[8], reso[9])
                    branches += ']'
                    
                else:
                    return '{"code": "DB/gen", "description": "database-transaction-error", "loc": "' + res['error'] + '"}'
                
                tags = '['
                res = localsql.fetchall("SELECT * FROM tags_tutorials WHERE `tr:id` = %s", result[0])
                if res['success']:
                    
                    if res['results']:
                        for reso in res['results']:
                            if res['results'].index(reso):
                                tags += ", "
                            tags += '"' + reso[0] + '"'
                    tags += ']'
                
                else:
                    return '{"code": "DB/gen", "description": "database-transaction-error", "loc": "' + res['error'] + '"}'
                    
                res = localsql.fetchone("SELECT * FROM users WHERE `ur:id` = %s", result[2])
                ret = localsql.fetchone("SELECT * FROM users_public WHERE `ur:id` = %s", result[2])
                
                upvs = 0 if result[5] == '' else result[5]
                downvs = 0 if result[6] == '' else result[6]
                rating = 100
                try:
                    rating = (1 - downvs / upvs)
                except Exception as e:
                    rating = 0
                
                if (res['success'] and ret['success']):
                    if (res['results'] and ret['results']):
                        user = '{{"username": "{}", "image": "{}"}}'.format(res['results'][1], ret['results'][1])
                        
                        return '{{"title": "{}", "tags": {}, "description": "{}", "support": {}, "rating": {}, "image": "{}", "url": "{}", "start": "{}", "author": {}, "steps": {}, "branches": {}, "similar": {}}}'.format(result[3], tags, result[4], '["support", "not", "set", "up"]', rating, result[7], "https://tutorialpaths.com/" + result[1].replace(':', '/'), "https://tutorialpaths.com/" + result[1].replace(':', '/'), user, steps, branches, [])
                
                return '{{"title": "{}", "tags": {}, "description": "{}", "support": {}, "rating": {}, "image": "{}", "url": "{}", "start": "{}", "author": "{}", "steps": {}, "branches": {}, "similar": {}}}'.format(result[3], tags, result[4], '["support", "not", "set", "up"]', rating, result[7], "https://tutorialpaths.com/" + result[1].replace(':', '/'), "https://tutorialpaths.com/" + result[1].replace(':', '/'), "false", steps, branches, [])
                
            else:
                return '{"code: "LOADER/TUT/01", "description": "tutorial-not-found"}'
        else:
            return '{"code": "DB/gen", "description": "database-transaction-error", "loc": "' + res['error'] + '"}'
    except Exception as e:
        return str(e)