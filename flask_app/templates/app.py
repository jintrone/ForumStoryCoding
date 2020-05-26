import json
from flask import Flask, request, flash, url_for, redirect, render_template, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, PasswordField, SubmitField, validators
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from collections import defaultdict
import random
import html

app = Flask(__name__)
config_file = "configuration.json"

with open(config_file) as f:
    configuration = json.load(f)

dburl_str = 'mysql+pymysql://{user}:{password}@{host_name}/{db}'.format(**configuration['database_config'])

app.config['SQLALCHEMY_DATABASE_URI'] = dburl_str
# app.config['SERVER_NAME'] = 'vaccinestories.ischool.syr.edu:80'

### CHECK HOW TO GENERATE SECRET KEY FOR FLASK
app.secret_key = "Add secret key here" 

login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)

# ----------- Declaration of DB Models ------------------------------------
class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, db.Sequence('users_seq'),primary_key=True)
    username = db.Column(db.String(255), unique=True)
    email = db.Column(db.String(255), unique=True)
    pwd = db.Column(db.Text)
    verified = db.Column(db.Boolean)

    def set_pwd(self, pwd):
        self.pwd = generate_password_hash(pwd)

    def check_pwd(self, pwd):
        return check_password_hash(self.pwd, pwd)

    def is_verified(self):
        return self.verified

class PostCodes(db.Model):
    __tablename__ = 'posts_codes'
    id = db.Column(db.Integer, db.Sequence('contents_seq'),primary_key=True)
    thread_id = db.Column(db.Integer) # !!! make it foreign to Json table
    post_id = db.Column(db.Integer)
    coded = db.Column(db.String(2048))
    coder = db.Column(db.String(2048))
    coded_date = db.Column(db.DateTime)


class WhalePostCodes(db.Model):
    __tablename__ = 'whales_codes'
    id = db.Column(db.Integer, db.Sequence('whale_posts_seq'),primary_key=True)
    post_id = db.Column(db.Integer) # !!! make it foreign to Json table
    story_id = db.Column(db.Integer)
    coder = db.Column(db.String(2048))

    character = db.Column(db.String(2048))
    event = db.Column(db.String(2048))
    goal = db.Column(db.String(2048))
    act = db.Column(db.String(2048))
    consequence = db.Column(db.String(2048))
    target = db.Column(db.String(2048))

    coded_date = db.Column(db.DateTime)


class JsonData(db.Model):
    __tablename__ = 'whale_json'

    id = db.Column(db.Integer,primary_key=True)
    json_data = db.Column(db.JSON)
    coders_count = db.Column(db.Integer)



# ----------- End of declaration of DB Models ------------------------------------

# login form
class LoginForm(Form):
    username = StringField('Username', [validators.DataRequired(), validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.DataRequired()])
    login = SubmitField('Login')


class RegisterForm(Form):
    username = StringField('Username', [validators.DataRequired(), validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Email()])
    password = PasswordField('Password', [validators.DataRequired(), validators.EqualTo('confirm_password', message="Passwords don't match")])
    confirm_password = PasswordField('Confirm Password', [validators.DataRequired()])
    register = SubmitField('Register')

class SearchThread(Form):
    search_field = StringField('Enter the value: ', [validators.DataRequired(), validators.Length(min=1, max=5)])
    search = SubmitField('Search')
# ----------- End of forms

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

# all the views
@app.route('/')
def start():
    return render_template('index.html')

@app.route('/register')
def register():
    form = RegisterForm()
    return render_template('register.html', form=form)

@app.route('/login')
def login():

    form = LoginForm()
    return render_template('login.html', form=form)

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
        flash("Logged out......")
    return render_template('index.html')

@app.route('/login_handler', methods=['POST'])
def login_handler():
    form = LoginForm(request.form)
    if form.validate():
        username = form.username.data
        pwd = form.password.data
        # get user
        user = Users.query.filter_by(username=username).first_or_404()
        if user.is_verified() and user.check_pwd(pwd):
            if current_user.is_authenticated:
                logout_user()

            login_user(user)
            flash("Logged in success ........")
            search_thread_form = SearchThread()

            coded_byuser = WhalePostCodes.query.filter(WhalePostCodes.coder==current_user.username).with_entities(WhalePostCodes.post_id).all()
            coded_list = list(set([j for i in coded_byuser for j in i]))
            coded_jsons = JsonData.query.filter(JsonData.id.in_(coded_list)).all()
            return render_template('search.html', form=search_thread_form, earlier_coded=coded_jsons)
    flash("Something is not correct in login ........")
    return render_template('login.html', form=form)

@app.route('/search_thread')
@login_required
def search_thread():
    search_thread_form = SearchThread()
    coded_byuser = WhalePostCodes.query.filter(WhalePostCodes.coder==current_user.username).with_entities(WhalePostCodes.post_id).all()
    coded_list = list(set([j for i in coded_byuser for j in i]))
    coded_jsons = JsonData.query.filter(JsonData.id.in_(coded_list)).all()

    return render_template('search.html', form=search_thread_form, earlier_coded=coded_jsons)

@app.route('/register_handler', methods=['POST'])
def register_handler():
    form = RegisterForm(request.form)
    if form.validate():
        if current_user.is_authenticated:
            logout_user()

        username = form.username.data
        email = form.email.data

        # get user
        try:
            user = Users(username=username, email=email, verified=True)
            user.set_pwd(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash("Try login now......")
            return render_template('index.html')
        except:
            flash('Error in registration form information! Contact for help.')
            return redirect(url_for('register'))

    flash('Error in registration!')
    return redirect(url_for('register'))

@app.route('/submit_code', methods=['POST'])
@login_required
def submit_code():

    result = request.get_json()
    new_result = None

    if result:

        thread_id = result[0]['thread_id']
        stories_lst = []

        stories_dictionary = {}

        if result[0]['stories']:
            for story_num, stories in enumerate(result[0]['stories']):

                story_contents = stories['items']
                tmp_story_dict = defaultdict(list)
                for story in story_contents:

                    if story_num not in stories_dictionary:
                        stories_dictionary[story_num] = {}

                    if story['type'] not in stories_dictionary[story_num]:
                        stories_dictionary[story_num][story['type']] = []

                    stories_dictionary[story_num][story['type']].append((story['text'], story['position']))

            for k, v in stories_dictionary.items():
                story_dict=dict()
                for k1, v1 in v.items():
                    story_dict[k1] = json.dumps(v1)
                    story_dict['story_id'] = k

                story_dict['post_id'] = thread_id
                story_dict['coder']=current_user.username
                story_dict['coded_date']=datetime.today()
                story_dict['character'] = story_dict.pop('char')

                contentCode = WhalePostCodes(**story_dict)
                db.session.add(contentCode)
                db.session.commit()
            # updating coders count
            thread_json = JsonData.query.filter_by(id=thread_id).first()
            thread_json.coders_count = thread_json.coders_count +1
            db.session.commit()

        not_coded_result = JsonData.query.filter(JsonData.coders_count<2).with_entities(JsonData.id).all()
        not_coded_set = set([j for i in not_coded_result for j in i])

        not_coded_byuser = WhalePostCodes.query.filter(WhalePostCodes.coder==current_user.username).with_entities(WhalePostCodes.post_id).all()
        not_coded_by_user_set = set([j for i in not_coded_byuser for j in i])
        next_post = list(not_coded_set - not_coded_by_user_set)
        if next_post:
            next_post_id = random.choice(next_post)#next_post[0]
            new_result = JsonData.query.filter_by(id=next_post_id).first_or_404()

            new_data = {'json_data': html.unescape(new_result.json_data)}
            new_data['id'] = next_post_id

            return jsonify(flask_result=new_data)
        else:
            flash('You do not have any further post to code!')
            return jsonify(flask_result=None)

@app.route('/search_handler', methods=['POST'])
@login_required
def search_handler():

    form = SearchThread(request.form)
    if form.validate():
        thread_id = form.search_field.data

        result = JsonData.query.filter_by(id=thread_id).first_or_404()
        return render_template('html_file.html', flask_result = result, prev_coding=None)

def get_fields(mapping_dictionary, type_fields, items):

    mapping_dictionary ['type'] = type_fields
    mapping_dictionary['text'] = items[0]
    mapping_dictionary['position'] = items[1]
    return mapping_dictionary


@app.route('/finder/')
@login_required
def finder():

    thread_id = request.args.get('thread_id')
    prev_coding = []
    stories_lst = []

    stories_dictionary = {}

    result = JsonData.query.filter_by(id=thread_id).first_or_404()
    db_codes = WhalePostCodes.query.filter(WhalePostCodes.post_id==thread_id, WhalePostCodes.coder==current_user.username).all()
    story_numbers = WhalePostCodes.query.filter(WhalePostCodes.post_id==thread_id, WhalePostCodes.coder==current_user.username).with_entities(WhalePostCodes.story_id).distinct()
    stories_num = [s.story_id for s in story_numbers]
    prev_coding = [{'items':[]} for i in range(len(stories_num))]

    for item_codes in db_codes:
        story_chars = item_codes.character
        event = item_codes.event
        goal = item_codes.goal
        act = item_codes.act
        consequence = item_codes.consequence
        target = item_codes.target


        for char_items in json.loads(story_chars):
            tmp_dict = {}
            get_fields(tmp_dict, 'char', char_items)
            prev_coding[item_codes.story_id]['items'].append(tmp_dict)

        for event_items in json.loads(event):
            tmp_dict = {}
            get_fields(tmp_dict, 'event', event_items)
            prev_coding[item_codes.story_id]['items'].append(tmp_dict)

        for goal_items in json.loads(goal):
            tmp_dict = {}
            get_fields(tmp_dict, 'goal', goal_items)
            prev_coding[item_codes.story_id]['items'].append(tmp_dict)

        for act_items in json.loads(act):
            tmp_dict = {}
            get_fields(tmp_dict, 'act', act_items)
            prev_coding[item_codes.story_id]['items'].append(tmp_dict)

        for consequence_items in json.loads(consequence):
            tmp_dict = {}
            get_fields(tmp_dict, 'consequence', consequence_items)
            prev_coding[item_codes.story_id]['items'].append(tmp_dict)

        for target_items in json.loads(target):
            tmp_dict = {}
            get_fields(tmp_dict, 'target', target_items)
            prev_coding[item_codes.story_id]['items'].append(tmp_dict)


    print(prev_coding)
    print('='*100)

    return render_template('html_file.html', flask_result = result, prev_coding= prev_coding)


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=8)


@app.errorhandler(404)
def page_not_found(e):

    flash('Cannot process request. Something was wrong .....')
    return render_template('index.html'), 404

@app.errorhandler(401)
def page_not_login(e):

    flash('You are not logged in. You MUST login .....')
    return render_template('index.html'), 401

if __name__ == '__main__':
   db.create_all()
   app.run()
   #app.run(host='0.0.0.0', port=80)
