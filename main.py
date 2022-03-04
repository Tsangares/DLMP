import iota_client,qrcode,io,hashlib,logging,random,segno
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers import RoundedModuleDrawer,HorizontalBarsDrawer
from qrcode.image.styles.colormasks import RadialGradiantColorMask

from badge import make_badge,mk_badge
from PIL import Image,ImageFont,ImageDraw

from werkzeug.middleware.proxy_fix import ProxyFix
import json,os,hashlib,datetime,time,logging,dateutil
import flask,requests,pymongo
from flask import Blueprint,Flask,request,redirect,render_template,session,flash,abort,make_response,send_file
from flask_pymongo import PyMongo
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager,login_required,login_user,UserMixin,current_user,logout_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,RadioField,SelectMultipleField,widgets,HiddenField
from wtforms.validators import DataRequired
from wtforms import validators
from bson.objectid import ObjectId
from urllib.parse import urlparse, urljoin
from flaskext.markdown import Markdown
from flask.sessions import SecureCookieSessionInterface
print(hashlib.algorithms_available)

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

#Flask 
app = Flask(__name__)
cred = json.load(open('dlmp_cred/cred.json'))
application = app
app.secret_key = cred['secret']
SALT = cred['salt'].encode('utf-8')
HASH_LEN = 11
VALID_HASH_LEN = [8,11]
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1 ,x_proto=1)
session_cookie = SecureCookieSessionInterface().get_signing_serializer(app)
app.config.update(
    SESSION_COOKIE_SAMESITE = "None",
    SESSION_COOKIE_SECURE = True
)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["60 per minute"],
)
#Mongodb
app.config['MONGO_DBNAME'] = 'iota_hat'
app.config["MONGO_URI"] = f"mongodb://{cred['username']}:{cred['password']}@{cred['db_domain']}:{cred['port']}/{cred['db']}?authSource=test"
mongo = PyMongo(app)

#Markdown
Markdown(app)

#IOTA
LOCAL_NODE_URL = "https://chrysalis-nodes.iota.org"
client = iota_client.Client(nodes_name_password=[[LOCAL_NODE_URL]], node_sync_disabled=True)


#Login - Accounts
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_message = u"Bonvolu ensaluti por uzi tiun paĝon."
csrf = CSRFProtect(app)

#User Accounts
def get_ip():
    return request.environ.get('HTTP_X_REAL_IP', None)

#Forms
class LoginForm(FlaskForm):
    passkey = StringField('Passkey',validators=[DataRequired()])
    
class HashForm(FlaskForm):
    passkey = StringField('Passkey',validators=[DataRequired()])
    
class EditForm(FlaskForm):
    name = StringField('Name or Title (Required)',validators=[DataRequired()])
    blurb = StringField('Subtitle')
    address = StringField('IOTA Address (for donations)')
    
class ContentForm(FlaskForm):    
    title = StringField('Title',validators=[DataRequired()])
    key = HiddenField()

link_actions = [
    ('open', "Open the link"),
    ('copy', "Copy the text"),
]
class LinkForm(ContentForm):
    link = StringField('Link',validators=[DataRequired()])
    action = RadioField('What action should the link take?', choices=link_actions,validators=[DataRequired()])
    
class TextForm(ContentForm):
    text = StringField('Subtext',validators=[DataRequired()])

class Badge:
    def __init__(self,badge):
        self.badge = badge
        self.key = badge['key']
        self.renoun = mongo.db.link.count_documents({'parent_key': self.key})
        self.name = badge['name']
        self.created = badge['time_created']
        self.influence = int((time.time() - badge['time_created'].timestamp())/10)
        
        
class User(UserMixin):
    def __init__(self, key):
        user = mongo.db.users.find_one({'key': key})
        self.last_refresh = time.time()
        self._id = user['_id']
        self.name = user.get('name','')
        self.account = user
        self.key = user['key']
        
    def refresh(self):
        if (time.time() - self.last_refresh) > 10:
            self.__init__(self.key)
    
    def get_content(self):
        return [c for c in mongo.db.content.find({'key': self.key})]

    @property
    def friends(self):
        self.refresh()
        friends_list = self.account.get('friends',[])
        return [mongo.db.users.find_one({'_id': objId}) for objId in friends_list]

    @property
    def friends_badges(self):
        badges = []
        for friend in self.friends:
            badges += User(friend['key']).badges
        return badges
    @property
    def friend_requests(self):
        self.refresh()
        friends_req_list = self.account.get('friend_requests',[])
        return [mongo.db.users.find_one({'_id': _id}) for _id in friends_req_list]
    
    @staticmethod
    def fix_link(link_obj):
        link = link_obj['link']
        if '//' not in link and '.' in link:
            link_obj['link'] = '//'+link
        return link_obj

    @property
    def badges(self):
        return [Badge(b) for b in mongo.db.badges.find({'owner': self._id})]
    
    def get_links(self):
        return [User.fix_link(c) for c in mongo.db.content.find({'key': self.key, 'type': 'link'})]
    
    def get_texts(self):
        return [c for c in mongo.db.content.find({'key': self.key, 'type': 'text'})]

    def add_link(self,content):
        self.add_content(content,'link')
        
    def add_text(self,content):
        self.add_content(content,'text')
        
    def add_content(self,content,type):
        mongo.db.content.insert_one({
            'key': self.key,
            'type': type
        } | content)
        
    def del_content(self,_id):
        mongo.db.content.delete_one({
            '_id': ObjectId(_id),
            'key': self.key
        })
        
    def claimed_badge(self):
        return mongo.db.badges.find_one({'key': self.key}) is not None

    def make_badge(self):
        if not self.claimed_badge():
            _,stats = make_badge(int(self.key,16))
            badge = stats | {
                'owner': self._id,
                'creator': self._id,
                'name': self.name,
                'key': self.key,
                'time_created': datetime.datetime.now(),
                'time_modified': datetime.datetime.now(),
                'ip_created': get_ip()
            }
            mongo.db.badges.insert_one(badge)
            return True
        else: return False

    def already_friend(self,key):
        friend = mongo.db.users.find_one({'key': key})
        if str(self._id) in [str(f) for f in friend.get('friends',[])]:
            return True
        elif str(self._id) in [str(f) for f in friend.get('friend_requests',[])]:
            return True
        return False
        
    def request_friend(self,key):
        self.refresh()
        if not self.already_friend(key):
            mongo.db.users.update_one({'key': key}, {
                '$push': {'friend_requests': self._id}
            })
            return True
        else:
            return False
        
    def reject_friend(self,key):
        self.refresh()
        friend = mongo.db.users.find_one({'key': key})
        mongo.db.users.update_one({'_id': self._id},{
            '$pull': {'friend_requests': friend['_id']}
        })
    
    def confirm_friend(self,key):
        self.refresh()
        friend = mongo.db.users.find_one({'key': key})
        if friend is None: return None
        friend_requested = str(friend['_id']) in [str(f) for f in self.friend_requests]
        already_my_friend = str(friend['_id']) in [str(f) for f in self.friends]
        if friend_requested and not already_my_friend:
            r1=mongo.db.users.update_one({'_id': friend['_id']}, {
                '$push': {'friends': self._id},
                '$pull': {'friend_requests': self._id}
            })
            r2=mongo.db.users.update_one({'_id': self._id}, {
                '$push': {'friends': friend['_id']},
                '$pull': {'friend_requests': friend['_id']}
            })
            print("Results update:",r1,r2)
            self.link_friend(friend)

    #Duplicate safe
    def link(self,friend):
        #Parent is me; child is friend
        if mongo.db.link.find_one({'parent_key': self.key,'child_key': friend['key']}) is None:
            mongo.db.link.insert_one({
                'parent_id': self._id,
                'parent_key': self.key,
                'child_id': friend['_id'],
                'child_key': friend['key'],
                'time_created': time.time()
            })
        if mongo.db.link.find_one({'child_key': self.key,'parent_key': friend['key']}) is None:
            mongo.db.link.insert_one({
                'parent_id': friend['_id'],
                'parent_key': friend['key'],
                'child_id': self._id,
                'child_key': self.key,
                'time_created': time.time()
            })
            
    @property
    def is_authenticated(self):
        return True

    @staticmethod
    def is_active():
        return True

    @staticmethod
    def is_anonymous():
        return False

    def get_key():
        return self.key

    def get_id(self):
        return self.key
    @staticmethod
    def create_user(key):
        ip = get_ip()
        timestamp = datetime.datetime.now()
        account = mongo.db.users.find_one({'key': key})
        if account is None:
            user = mongo.db.users.insert_one({
                'key': key,
                'ip_created': ip,
                'time_created': timestamp
            })
        login_user(User(key=key))
        return redirect(f'/{key}/admin')

#@app.route('/refresh_links/',methods=['GET'])
def refresh_links():
    for user in mongo.db.users.find({'friends': {'$exists': True}}):
        me=User(user['key'])
        print(me.name,me._id)
        
        friends = me.friends
        for friend in friends:
            print(f'{me.name} is friending {friend["name"]}')
            me.link(friend)
    return "done."
        
        
@login_manager.user_loader
def load_user(key):
    return User(key)
        
@login_manager.unauthorized_handler
def unauthorized_callback():
    next_page = '/'.join(request.path.split('/')[:-1])
    return redirect(f'/unauthorized?next={next_page}')

@app.route('/unauthorized',methods=["GET"])
def unauthorize_page():
    next_page = request.args.get('next','/')
    return f'You are not allowed to view this page! <meta http-equiv="refresh" content="2; url={next_page}" />'

def unique_hash(data):
    salted = str(data).lower().replace(' ','').encode('utf-8') + SALT
    sha = hashlib.sha3_512()
    for i in range(16):
        sha.update(salted)
    return sha.hexdigest()[:HASH_LEN]

def get_rand_key():
    return ' '.join([''.join([str(random.randint(0,9)) for _ in range(3)]) for _ in range(4)])

@app.route('/create/',methods=['GET','POST'])
def hash_page(custom=False):
    #key = request.form.get('passkey',None)
    #hashed = None
    #if key is None or len(key)<:
    #    key = get_rand_key()
    key = get_rand_key()
    hashed = unique_hash(key)
    form = HashForm()
    return render_template('create_account.html',hashed=hashed,key=key,form=form,custom=custom)

@app.route('/',methods=['GET'])
def get_homepage():
    key = request.args.get('key',None)
    if key is not None:
        return redirect(f'/{key}')
    error = request.args.get('error',None)
    error_message = None
    if error == 'key':
        error_message = "The key/url you provided is invalid."
    return render_template('index.html',error=error_message)


def send_img(string):
    #img = qrcode.make(string.upper(),back_color="white")
    img = segno.make_qr(string.lower())
    img_io = io.BytesIO()
    #img.save(img_io,'png',scale=10,border=1)
    img.save(img_io,'png', dark=(0,0,0,1),light=(0,0,0,0), scale=10)
    img_io.seek(0)
    return send_file(img_io,mimetype="image/png")

@app.route('/qr/',methods=['GET'])
def get_qr_url():
    q = request.args.get('q',None)
    if q is not None:
        return send_img(str(q))
    return "error"
    

@app.route('/qr/<string>',methods=['GET'])
def get_qr_image(string):
    return send_img(string)


@app.route('/<key>',methods=['GET'])
def get_iota_view(key):
    if len(key) not in VALID_HASH_LEN:
        return redirect('/?error=key')
    account = mongo.db.users.find_one({'key': key})
    if account is None:
        form = LoginForm()
        return render_template('login.html',key=key,form=form,failed=False)
    elif 'address' not in account:
        return redirect(f'/{key}/admin')
    name = account.get('name',None)
    address = account.get('address',None)
    blurb = account.get('blurb',None)
    failed = request.args.get('failed',False)
    user = User(key=key)
    logged_in = current_user.is_authenticated
    if logged_in and key==current_user.key:
        friends = current_user.friends_badges
        friend_requests = current_user.friend_requests
    else:
        friends = user.friends_badges
        friend_requests = []
    print(friends,friend_requests)
    
    links = user.get_links()
    texts = user.get_texts()
    minted = user.claimed_badge()
    badges = user.badges
    return render_template(
        'account.html',
        address=address,
        user=user,
        current_user=current_user,
        name=name,
        blurb=blurb,
        key=key,
        failed=failed,
        logged_in=logged_in,
        links=links,
        texts=texts,
        minted=minted,
        badges=badges,
        friends=friends,
        friend_requests=friend_requests
    )


    


@app.route('/<key>/admin',methods=['GET'])
def iota_key_admin(key):
    if not current_user.is_authenticated:
        form = LoginForm()
        return render_template('login.html',key=key,form=form,failed=False)
    elif current_user.key == key:
        edit_account_form = EditForm(data=current_user.account)
        links = current_user.get_links()
        texts = current_user.get_texts()
        return render_template(
            'edit_account/edit_account.html',
            key=key,
            form=edit_account_form,
            account=current_user.account,
            deleted=request.args.get('deleted',None),
            links=links,
            texts=texts
        )
    else:
        #Possibly add a logout here!
        return redirect(f'/{key}?failed=True')

@app.route('/<key>/admin',methods=['POST'])
@login_required
def iota_key_admin_edit(key):
    if not current_user.is_authenticated:
        form = LoginForm()
        return render_template('login.html',key=key,form=form,failed=False)
    elif current_user.key == key:
        links = current_user.get_links()
        texts = current_user.get_texts()
        name = request.form.get('name','').strip()
        address = request.form.get('address','').strip()
        blurb = request.form.get('blurb','').strip()
        edit_account_form = EditForm()
        if address != '' and not client.is_address_valid(address):
            error_message = "The address given is not a valid IOTA address!"
            return render_template(
                'edit_account/edit_account.html',
                key=key,
                form=edit_account_form,
                account=current_user.account,
                error=error_message,
                links=links,
                texts=texts,
                deleted=request.args.get('deleted',None),
            )
        else:
            mongo.db.users.update_one({'key': key},{'$set': {
                'address': address,
                'name': name,
                'blurb': blurb
            }})
            if request.form.get('edit',False):
                return render_template(
                    'edit_account/edit_account.html',
                    key=key,
                    form=edit_account_form,
                    account=current_user.account,
                    notify="Saved!",
                    links=links,
                    texts=texts,
                    deleted=request.args.get('deleted',None),
                )
            elif request.form.get('add_link',False):
                return redirect(f'/{key}/admin/add/link')
            elif request.form.get('add_text',False):
                return redirect(f'/{key}/admin/add/text')
            else:
                return redirect(f'/{key}')
    else:
        #Possibly add a logout here!
        return redirect(f'/{key}')

#LINK
@app.route('/<key>/admin/add/link',methods=['GET'])
def add_link_view(key):
    if not current_user.is_authenticated or current_user.key != key:
        return redirect(f'/{key}')
    form = LinkForm(key=key)
    return render_template('edit_account/add_links.html',key=key,form=form)

def clean_link(string):
    return string.replace('"','').replace("'",'')

@app.route('/<key>/admin/add/link',methods=['POST'])
def add_link(key):
    if not current_user.is_authenticated or current_user.key != key:
        return redirect(f'/{key}')
    content = {
        'title': request.form.get('title',None),
        'link': clean_link(request.form.get('link',None)),
        'action': request.form.get('action',None),
    }
    current_user.add_link(content)
    return redirect(f'/{key}/admin')

#TEXT
@app.route('/<key>/admin/add/text',methods=['GET'])
def add_text_view(key):
    if not current_user.is_authenticated or current_user.key != key:
        return redirect(f'/{key}')
    form = TextForm(key=key)
    return render_template('edit_account/add_text.html',key=key,form=form)

@app.route('/<key>/admin/add/text',methods=['POST'])
def add_text(key):
    if not current_user.is_authenticated or current_user.key != key:
        return redirect(f'/{key}')
    content = {
        'title': request.form.get('title',None),
        'text': request.form.get('text',None),
    }
    current_user.add_text(content)
    return redirect(f'/{key}/admin')

@app.route('/<key>/admin/del',methods=['GET'])
def del_content(key):
    if not current_user.is_authenticated or current_user.key != key:
        return redirect(f'/{key}')
    _id = request.args.get('q',None)
    _type = request.args.get('type',None)
    return redirect(f'/{key}/admin?deleted={_type}')

@app.route('/<key>/mint',methods=['GET'])
@login_required
def mint_badge(key):
    if current_user.make_badge():
        return redirect(f'/{key}?success=1')
    else:
        return redirect(f'/{key}?success=0')

@app.route('/<key>',methods=['POST'])
def create_iota_account(key):
    passkey = request.form.get('passkey','')
    hashed_pass = unique_hash(passkey)
    if hashed_pass[:len(key)].upper() == key.upper():
        return User.create_user(key)
    else:
        form = LoginForm()
        return render_template('login.html',key=key,form=form,failed=True,hashed=hashed_pass[:len(key)])

@app.route('/<key>/logout',methods=['GET'])
def logout(key):
    logout_user()
    return redirect(f'/{key}')

@app.route('/generate',methods=['GET'])
def mnemonic():
    mnemonic = client.generate_mnemonic()
    print("Mnemonic:",mnemonic)
    seed = client.mnemonic_to_hex_seed(mnemonic)
    address_changed_list = client.get_addresses(
        seed=seed,
        account_index=0,
        input_range_begin=0,
        input_range_end=1,
        get_all=False
    )
    address,change = address_changed_list[0]
    print('Address:',address)
    return f"<tt><b>Mnemonic:</b> {mnemonic}<br><b>Address:</b> {address}</tt>"
def send_pdf(img):
    img_io = io.BytesIO()
    img.save(img_io,'pdf')
    img_io.seek(0)    
    return send_file(img_io,mimetype='application/pdf')

def send_png(img):
    img_io = io.BytesIO()
    img.save(img_io,'png')
    img_io.seek(0)    
    return send_file(img_io,mimetype='image/png')

font = ImageFont.truetype("static/ubuntu.ttf",66)
smallfont = ImageFont.truetype("static/ubuntu.ttf",49)
def mk_account():
    key = get_rand_key()
    hashed = unique_hash(key)
    url = f"YQue.net/{hashed}"    
    width = int(8.5*300/4)
    img = Image.new(mode="RGB",size=(width,width+175),color="white")
    qr = segno.make_qr(url.lower())
    qr = qr.to_pil(dark="black",light="white",scale=20,border=0)
    offset=int((width-qr.width)/2)
    img.paste(qr,(offset,offset))
    
    #Text
    w,h=font.getsize(key)
    offset = int((width-w)/2)
    draw = ImageDraw.Draw(img)
    draw.text((offset,width),key,(0,0,0),font=font)
    draw.text((offset,width+2*h),url,(0,0,0),font=smallfont)
    return img

@app.route('/badge',methods=['GET'])
def get_badge_random():
    badge,stats = mk_badge()    
    return send_png(badge)

@app.route('/badge/random/<key>',methods=['GET'])
def get_badge_random_key(key):
    badge,stats = mk_badge()
    return send_png(badge)

@app.route('/badge/<key>',methods=['GET'])
def get_badge(key):
    badge,stats = make_badge(int(key,16))
    return send_png(badge)

@app.route('/create/page',methods=['GET'])
def mk_page():
    page = Image.new(mode="RGB",size=(int(8.5*300),int(11*300)),color="white")
    pane = mk_account()
    cols = int(page.width/pane.width)
    rows = int(page.height/pane.height)
    for c in range(cols):
        for r in range(rows):
            page.paste(mk_account(),(c*pane.width,r*pane.height))
    return send_pdf(page)

@app.route('/about',methods=['GET'])
def get_about_us():
    return render_template('about.html')

@app.route('/<key>/connect',methods=['GET'])
@login_required
def connect_account(key):
    r=current_user.request_friend(key)
    return redirect(f'/{key}?friend_request={r}')

@app.route('/<key>/accept',methods=['GET'])
@login_required
def confirm_friend_account(key):
    r=current_user.confirm_friend(key)
    return redirect(f'/{key}?friend_request={r}')

@app.route('/<key>/reject',methods=['GET'])
@login_required
def reject_friend_account(key):
    r=current_user.reject_friend(key)
    return redirect(f'/{key}?friend_request={r}')

if __name__=="__main__":
    app.run(host='localhost',port='8099',debug=True)


