import qrcode,io,hashlib,logging,random,segno
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers import RoundedModuleDrawer,HorizontalBarsDrawer
from qrcode.image.styles.colormasks import RadialGradiantColorMask

#Relative import
try:
    from .badge import make_badge,mk_badge
except ImportError:
    from badge import make_badge,mk_badge

from PIL import Image,ImageFont,ImageDraw

from werkzeug.middleware.proxy_fix import ProxyFix
import json,os,hashlib,datetime,time,logging
import flask,requests,pymongo,base64,math
from flask import Blueprint,Flask,request,redirect,render_template,session,flash,abort,make_response,send_file
from flask_pymongo import PyMongo
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager,login_required,login_user,UserMixin,current_user,logout_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,RadioField,SelectMultipleField,widgets,HiddenField,FileField,EmailField,TextAreaField
from wtforms.validators import DataRequired, Email
from wtforms import validators
from bson.objectid import ObjectId
from urllib.parse import urlparse, urljoin
from flaskext.markdown import Markdown
from flask.sessions import SecureCookieSessionInterface

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from PIL import Image, ImageOps
import exifread
from io import BytesIO
import numpy as np
from pillow_heif import register_heif_opener
import logging
from dotenv import load_dotenv
import os
cwd = os.getcwd()

load_dotenv()
logging.basicConfig(level=logging.INFO)
register_heif_opener()

#Flask 
app = Flask(__name__)

cred_file = 'dlmp_cred/cred.json'
if os.path.exists(cred_file):
    cred = json.load(open(cred_file))
else:
    cred = None
    
def is_valid_address(address):
    #return len(string) >= 60 and ('iota' in string or 'smr' in string)
    response = requests.get(f"https://helper.yque.net/address/{address}").text.strip() == "True"
    return response

def get_cred(key):
    if cred is not None and key in cred:
            return cred[key]
    elif key in os.environ:
        return os.environ[key]
    
def get_mongo_uri():
    if cred is not None:
        return f"mongodb://{cred['username']}:{cred['password']}@{cred['db_domain']}:{cred['port']}/{cred['db']}?authSource=test"
    else:
        return os.environ["MONGO_URI"]
    
application = app
app.secret_key = get_cred('secret')
SALT = get_cred('salt').encode('utf-8')
HASH_LEN = 11
VALID_HASH_LEN = [8,11]
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1 ,x_proto=1)
session_cookie = SecureCookieSessionInterface().get_signing_serializer(app)
app.config.update(
    SESSION_COOKIE_SAMESITE = "None",
    SESSION_COOKIE_SECURE = True
)
MONGO_URI = get_mongo_uri()
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per minute"],
    storage_uri=MONGO_URI,
    strategy="fixed-window"
)
#Mongodb
app.config['MONGO_DBNAME'] = 'iota_hat'
app.config["MONGO_URI"] = MONGO_URI
mongo = PyMongo(app)

#Markdown
Markdown(app)

#Login - Accounts
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_message = u"Bonvolu ensaluti por uzi tiun paĝon."
csrf = CSRFProtect(app)

#User Accounts
def get_ip():
    return request.environ.get('HTTP_X_REAL_IP', request.environ.get('REMOTE_ADDR',None))

@app.template_filter('strftime')
def _jinja2_filter_datetime(date, fmt=None):
    native = date.replace(tzinfo=None)
    format='%b %d, %Y'
    return native.strftime(format) 

#Forms
class LoginForm(FlaskForm):
    passkey = StringField('Passkey',validators=[DataRequired()])
    
class HashForm(FlaskForm):
    passkey = StringField('Passkey',validators=[DataRequired()])
    
    
class ContentForm(FlaskForm):    
    title = StringField('Title',validators=[DataRequired()])
    key = HiddenField()

class ImageForm(FlaskForm):
    title = StringField('Title',validators=[DataRequired()])
    image = FileField('Image File', [validators.regexp(r'^[^/\\]\.jpg$')])
    def validate_image(form, field):
        if field.data:
            field.data = re.sub(r'[^a-z0-9_.-]', '_', field.data)
    
class EditForm(FlaskForm):
    name = StringField('Name or Title (Required)',validators=[DataRequired()])
    blurb = StringField('Subtitle')
    address = StringField('IOTA or Shimmer Address (for donations)')
    redirect = StringField('Permanent Rediret for your DLMP (One Time Use) (NEEDS https://)')
    
link_actions = [
    ('open', "Open the link"),
    ('copy', "Copy the text"),
]
class LinkForm(ContentForm):
    link = StringField('Link',validators=[DataRequired()])
    action = RadioField('What action should the link take?', choices=link_actions,validators=[DataRequired()])
    
class TextForm(ContentForm):
    text = StringField('Subtext',validators=[DataRequired()])

class RedirectForm(ContentForm):
    link = StringField('Title',validators=[DataRequired()])

class ContactForm(FlaskForm):
    hidden_key = HiddenField()
    key = StringField('Micropage Link (if there is an issues with your webpage)')
    name = StringField('Your Name',validators=[DataRequired()])
    email = EmailField('Your Email to Respond',validators=[DataRequired(),Email()])
    message = TextAreaField('Message',validators=[DataRequired()])

class Badge:
    def __init__(self,badge,image=None):
        self.badge = badge
        self.image = None
        self.key = badge['key']
        self.renoun = mongo.db.link.count_documents({'parent_key': self.key})
        self.name = badge['name']
        self.created = badge['time_created']
        self.influence = int((time.time() - badge['time_created'].timestamp())/10)
    def set_image(self,image):
        self.image = image
        
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
            f = User(friend['key'])
            badge = f.badge
            badge.set_image(f.get_image())
            badges.append(badge)
        return badges
    
    def get_friend_requests(self):
        self.refresh()
        friends_req_list = self.account.get('friend_requests',[])
        friends = [mongo.db.users.find_one({'_id': _id}) for _id in friends_req_list]
        for friend in friends:
            friend['image'] = User(friend['key']).get_image()
        return friends
    
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
    
    @property
    def badge(self):
        badge = mongo.db.badges.find_one({'owner': self._id})
        if badge is None:
            return Badge(mongo.db.users.find_one({'_id': self._id}))
        else:
            return Badge(badge)
    
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
        if friend is None: return False
        friend_requested = str(friend['_id']) in [str(f['_id']) for f in self.friend_requests]
        already_my_friend = str(friend['_id']) in [str(f['_id']) for f in self.friends]
        if friend_requested and not already_my_friend:
            r1=mongo.db.users.update_one({'_id': friend['_id']}, {
                '$push': {'friends': self._id},
                '$pull': {'friend_requests': self._id}
            })
            r2=mongo.db.users.update_one({'_id': self._id}, {
                '$push': {'friends': friend['_id']},
                '$pull': {'friend_requests': friend['_id']}
            })
            app.logger.info(f"Results update: {r1} {r2}")
            self.link(friend)
            return True
        if not friend_requested:
            return "no-friend-request"
        elif not already_my_friend:
            return "already-friend"

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
    
    
    def upload_image(self,image):
        filename = image.filename
        
        filetype = filename.split('.')[-1].lower()
        if filetype=='jpg': filetype='jpeg'
        if filetype=='heif': filetype='jpeg'
        def process_image(image):
            tags = exifread.process_file(image.stream, details=True)
            exif = {tag:str(tags[tag]) for tag in tags.keys()}
            img = Image.open(image.stream)
            img = ImageOps.exif_transpose(img)
            width,height = img.size
            #crop
            length = min([width,height])
            app.logger.info(f"Cropping image of resoultion ({width},{height})")
            center = np.array((width/2,height/2))
            left,upper = (center-length/2).tolist()
            right,lower = (left+length,upper+length)
            img = img.crop((left,upper,right,lower))
            if max(img.size)>1_000:
                img = img.resize((1_000,1_000))
            buffer = BytesIO()
            img.save(buffer, format=filetype)
            
            return base64.b64encode(buffer.getvalue()), exif, *img.size
        image_encoded,exif,width,height = process_image(image)
        image = mongo.db.images.insert_one({
            'key': self._id,
            'time_created': datetime.datetime.now(),
            'time_modified': datetime.datetime.now(),
            'data': image_encoded,
            'filetype': filetype,
            'ip_created': get_ip(),
            'agent': request.user_agent.string,
            'width': width,
            'height': height,
            'exif': exif
        })
        self.set_image(image.inserted_id)
        
    def get_images(self,render=True):
        images =  [c for c in mongo.db.images.find({'key': self._id})]
        images.reverse()
        if render:
            for image in images:
                image['data'] = image['data'].decode('utf-8')
            return images
        return images
    
    def get_image(self):
        if 'display_image' in self.account:
            image = mongo.db.images.find_one({'key': self._id,'_id': self.account['display_image']})
        else:
            images = self.get_images(render=False)
            if len(images)==0:
                return None
            image = images[0]
        
        image['data'] = image['data'].decode('utf-8')
        return image
    
    def set_image(self,image_id):
        self.refresh()
        if isinstance(image_id,str):
            image_id = ObjectId(image_id)
        image = mongo.db.images.find_one({'key': self._id, '_id': image_id})
        if image is None: return
        mongo.db.users.update_one({'key': self.key},{'$set': {
            'display_image': image['_id']
        }})
        self.account['display_image'] = image['_id']
        
    def del_image(self,image_id):
        image_id = ObjectId(image_id)
        mongo.db.images.delete_one({'key': self._id, '_id': image_id})
    
    def toggle_badge(self):
        self.refresh()
        if 'badge_enabled' in self.account and self.account['badge_enabled']:
            mongo.db.users.update_one({'key': self.key},{'$set': {
                'badge_enabled': False
            }})
            self.account['badge_enabled'] = False
        else:
            mongo.db.users.update_one({'key': self.key},{'$set': {
                'badge_enabled': True
            }},upsert=True)
            self.account['badge_enabled'] = True
        return self.account['badge_enabled']
    
    def set_redirect(self):
        self.refresh()
        delete = request.form.get('del_redirect',None)
        link = request.form.get('redirect',None)
        if delete is not None and 'redirect' in self.account:
            #Delete
            mongo.db.users.update_one({'key': self.key},{'$unset': {'redirect': ""}})
            self.account['redirect'] = ""
            return True
        elif link is not None:
            if validate_link(link):
                mongo.db.users.update_one({'key': self.key},{'$set': {
                    'redirect': link
                }},upsert=True)
                self.account['redirect'] = link
                return True
            else: return False
        return False
            
def validate_link(link):
    return r'https://' in link.lower() and r'.' in link.lower()


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
    view = 'view' in request.args
    edit = 'edit' in request.args
    if key is not None:
        key=[k for k in key.replace(' ','').strip().split('/') if len(k) in VALID_HASH_LEN]
        if len(key) > 0: key=key[0]
        else: key is None
        if view and key is not None:
            return redirect(f'/{key}')
        elif edit and key is not None:
            return redirect(f'/{key}/admin')
        else:
            return redirect(f'/?error=key')
    error = request.args.get('error',None)
    error_message = None
    if error == 'key':
        error_message = "The key/url you provided is invalid."
    elif error == 'email_success':
        error_message = "Email sucessfully sent."
    elif error == 'email_invalid':
         error_message = "Email failed to send."
    key = current_user.key if current_user.is_authenticated else None
    contact_form = ContactForm(key=key,hidden_key=key)
    return render_template('index.html',error=error_message,contact_form=contact_form,key=key)

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


@app.after_request
def after_request_callback(response):
    try:
        track_visit()
    except NameError:
        pass
    return response
def track_visit():
    ip = get_ip()
    timestamp = datetime.datetime.now()
    endpoint = request.path
    if 'badge' in endpoint or 'qr' in endpoint: return
    domain = request.host
    user_agent = request.user_agent.string    
    crumb = mongo.db.visits.find_one({'ip': ip,'endpoint': endpoint,'domain': domain})
    if crumb is None:
        keys = [user.key] if current_user.is_authenticated else []
        mongo.db.visits.insert_one({
            'ip': ip,
            'created': timestamp,
            'modified': timestamp,
            'visits': 1,
            'endpoint': endpoint,
            'domain': domain,
            'keys': keys,
            'user_agents': [user_agent]
        })
    else:
        key = user.key if current_user.is_authenticated else None
        mongo.db.visits.update_one({'_id': crumb['_id']},{
            '$inc': {'visits': 1},
            '$set': {'modified': timestamp},
            '$addToSet': {'keys': key},
            '$addToSet': {'user_agents': user_agent}
        })


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
    image = user.get_image()
    logged_in = current_user.is_authenticated
    if logged_in and key==current_user.key:
        friends = current_user.friends_badges
        friend_requests = current_user.get_friend_requests() #get images
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
        image=image,
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
        image_form = ImageForm()
        image = current_user.get_image()
        links = current_user.get_links()
        texts = current_user.get_texts()
        return render_template(
            'edit_account/edit_account.html',
            key=key,
            form=edit_account_form,
            image_form=image_form,
            account=current_user.account,
            deleted=request.args.get('deleted',None),
            links=links,
            texts=texts,
            image=image
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
        return_to_edit = request.form.get('edit',False)
        error_message=None
        new_image = request.files['image']
        if new_image.filename == "": new_image=None
        if new_image is not None:
            return_to_edit=True
            current_user.upload_image(new_image)
        if request.form.get('set_redirect',False) or request.form.get('del_redirect',False):
            return_to_edit=True
            successful_redirect = current_user.set_redirect()
            if not successful_redirect:
                error_message = "Your redirect link was malformed."
        image = current_user.get_image()
        image_form = ImageForm()
        links = current_user.get_links()
        texts = current_user.get_texts()
        name = request.form.get('name','').strip()
        address = request.form.get('address','').strip()
        blurb = request.form.get('blurb','').strip()
        edit_account_form = EditForm(data=current_user.account)
        # Entered an iota address
        if address != '' and not is_valid_address(address):
            #ERROR PATH
            error_message = "The address given is not a valid IOTA address!"
            return render_template(
                'edit_account/edit_account.html',
                key=key,
                form=edit_account_form,
                image_form=image_form,
                account=current_user.account,
                error=error_message,
                links=links,
                texts=texts,
                image=image,
                deleted=request.args.get('deleted',None),
            )
            
        #SUCCESS PATH
        mongo.db.users.update_one({'key': key},{'$set': {
            'address': address,
            'name': name,
            'blurb': blurb
        }})
        #Return to edit page if they uploaded and image of edit is false
        #If edit is  True then the person is still editing their page.
        if return_to_edit:
            return render_template(
                'edit_account/edit_account.html',
                key=key,
                form=edit_account_form,
                image_form=image_form,
                account=current_user.account,
                error=error_message,
                notify="Saved!",
                links=links,
                texts=texts,
                image=image,
                deleted=request.args.get('deleted',None),
            )
        elif request.form.get('add_link',False):
            #Return to page because they added a link
            return redirect(f'/{key}/admin/add/link')
        elif request.form.get('add_text',False):
            #Return to page because they added a text blob
            return redirect(f'/{key}/admin/add/text')
        else:
            return redirect(f'/{key}')
    else:
        #Possibly add a logout here!
        return redirect(f'/{key}')
    
#IMAGES
@app.route('/<key>/admin/images/',methods=['GET','POST'])
@login_required
def get_account_images(key):
    if not current_user.is_authenticated or current_user.key != key:
        return redirect(f'/{key}')
    images = current_user.get_images()
    return render_template('edit_account/edit_images.html',key=key,account=current_user.account,images=images)

@app.route('/<key>/admin/del_image/<image_id>',methods=['GET'])
@login_required
def delete_account_image(key,image_id):
    if not current_user.is_authenticated or current_user.key != key:
        return redirect(f'/{key}')
    current_user.del_image(image_id)
    images = current_user.get_images()
    return render_template('edit_account/edit_images.html',key=key,account=current_user.account,images=images)


@app.route('/<key>/admin/set_image/<image_id>',methods=['GET'])
@login_required
def set_account_image(key,image_id):
    if not current_user.is_authenticated or current_user.key != key:
        return redirect(f'/{key}')
    current_user.set_image(image_id)
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
    current_user.del_content(_id)
    return redirect(f'/{key}/admin?deleted={_type}')

@app.route('/<key>/mint',methods=['GET'])
@login_required
def mint_badge(key):
    if current_user.make_badge():
        return redirect(f'/{key}?success=1')
    else:
        return redirect(f'/{key}?success=0')

@app.route('/<key>/admin/badge')
@login_required
def toggle_badge(key):
    if not current_user.is_authenticated:
        form = LoginForm()
        return render_template('login.html',key=key,form=form,failed=False)
    elif current_user.key == key:
        current_user.toggle_badge()
    return redirect(f'/{key}')
        

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
    return {'error': "This endpoint is removed."}
    
def send_pdf(img):
    img_io = io.BytesIO()
    img.save(img_io,'pdf')
    img_io.seek(0)    
    return send_file(img_io,mimetype='application/pdf')

def send_png(img):
    img_io = io.BytesIO()
    img.save(img_io,'png',dpi=(int(300),int(300)))
    img_io.seek(0)    
    return send_file(img_io,mimetype='image/png')

font = ImageFont.truetype("api/static/ubuntu.ttf",66)
smallfont = ImageFont.truetype("api/static/ubuntu.ttf",49)
def mk_account(rows=4,columns=3,page_width=7,page_height=10):
    key = get_rand_key()
    w,h=font.getsize(key)
    h_offset = 10
    hashed = unique_hash(key)
    url = f"YQue.net/{hashed}"    
    width = int(page_width*300/columns)
    height = int(page_height*300/rows)

    img = Image.new(mode="RGB",size=(width,height),color="white")
    qr = segno.make_qr(url.lower())
    qr = qr.to_pil(dark="black",light="white",scale=20,border=0)
    offset_X=int((width-qr.width)/2)
    offset_Y=int((height-qr.height-2*h-h_offset)/2)
    img.paste(qr,(offset_X,offset_Y))

    
    #Text
    offset = int((width-w)/2)
    draw = ImageDraw.Draw(img)
    draw.text((offset,height-h-h_offset),key,(0,0,0),font=font)
    draw.text((offset,height-2*h-h_offset),url,(0,0,0),font=smallfont)
    
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


@app.route('/create/page/<int:rows>/<int:cols>',methods=['GET'])
def make_custom_page(rows,cols):
    page_width=8.5
    page_height=10
    page = Image.new(mode="RGB",size=(int(page_width*300),int(page_height*300)),color="white")
    get_pane = lambda: mk_account(rows,cols,page_width,page_height)
    pane = get_pane()
    verticles = int(page.width/pane.width)
    horizontals = int(page.height/pane.height)

    
    for c in range(verticles):
        for r in range(horizontals):
            page.paste(get_pane(),(c*pane.width,r*pane.height))
    return send_png(page)
    
@app.route('/create/page',methods=['GET'])
def mk_page():
    return make_custom_page(3,4)
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
    return redirect(f'/{current_user.key}?friend_request={r}')

@app.route('/<key>/reject',methods=['GET'])
@login_required
def reject_friend_account(key):
    r=current_user.reject_friend(key)
    return redirect(f'/{key}?friend_request={r}')


@app.route("/contact_us/email",methods=['POST'])
def contact_us_email():
    contact_form = ContactForm()
    if contact_form.validate_on_submit():
        email = {
            'name': request.form.get("name","No Name"),
            'email': request.form.get("email",None),
            'message': request.form.get("message",None),
            'key': request.form.get('key',None),
            'hidden_key': request.form.get('hidden_key',None)
        }
        if not os.path.exists('emails'):
            os.mkdir('emails')
        clock=int(time.time())
        with open(f'./emails/{clock}.json','w+') as f:
            json.dump(email,f,indent=2)
        return redirect(f'/?error=email_success')
    else:
        url = request.form.get("url",None)
        if url is None:
            return {'error': 'invalid request'}
        else:
            return redirect('/?error=email_invalid')

@app.route('/balance/<address>')
def get_balance(address: str):
    is_valid = is_valid_address(address)
    if not is_valid:
        return {'error': 'Not a valid address', 'address': address, 'valid': is_valid, 'valid_type': type(is_valid)}
    return requests.get(f"https://helper.yque.net/balance/{address}").text

if __name__=="__main__":
    app.run(host='localhost',port='8099',debug=True)


