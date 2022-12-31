from flask import Flask, g, request, jsonify, session, redirect, url_for, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from http import HTTPStatus
from flask_login import LoginManager, login_user, confirm_login, login_required, logout_user, current_user, UserMixin
import os
import json
from datetime import timedelta


app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.sqlite')
app.secret_key = 'c219c59a640e3649aab348aa55e4bc38833e4d6c8ee1ff0ffa9a60e75619ee2b'

db = SQLAlchemy(app)
ma = Marshmallow(app)
bc = Bcrypt(app)
# CORS(app, supports_credentials=True)
CORS(app)
login_manager = LoginManager()
login_manager.init_app(app)

delta = timedelta(
    days=30
)


class Article(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    article_meta_data = db.Column(db.String, nullable = False)
    article_content = db.Column(db.String, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __init__(self, article_meta_data, article_content, user_id):
        self.article_meta_data = article_meta_data
        self.article_content = article_content
        self.user_id = user_id


class Book(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    book_meta_data = db.Column(db.String, nullable = False)
    book_content = db.Column(db.String, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __init__(self, book_meta_data, book_content,user_id):
        self.book_meta_data = book_meta_data
        self.book_content = book_content
        self.user_id = user_id



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String, nullable = False)
    password = db.Column(db.String, nullable = False)
    email = db.Column(db.String, nullable = True, unique = True)
    user_books = db.relationship("Book", backref="user", cascade='all, delete, delete-orphan', lazy=True)


    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email
        # self.is_active = is_active


class UserSchema(ma.Schema):
    class Meta: 
        model = User
        fields = ("id", "username", "password", "email")


class BookSchema(ma.Schema):
    class Meta:
        modal = Book
        fields = ("id", "book_meta_data", "book_content")


class ArticleSchema(ma.Schema):
    class Meta:
        modal = Article
        fields = ("id", "article_meta_data", "article_content")
            


user_schema = UserSchema()
many_user_schema = UserSchema(many=True)

book_schema = BookSchema()
many_book_schema = BookSchema(many=True)

article_schema = ArticleSchema()
many_article_schema = ArticleSchema(many=True)

# login_manager.login_view = "authorized_user"

@login_manager.user_loader
def load_user(id):
    # return User.query.get(int(id))
    return db.session.query(User).get(id)

@login_manager.unauthorized_handler
def unauthorized():
    if request.blueprint == 'api':
        abort(HTTPStatus.UNAUTHORIZED)
    # return redirect(url_for('authorized_user'))
    return jsonify("UNAUTHORIZED")




# ************** Test Routes *************

@app.route('/')
def hello():
    return 'HOME PAGE ..... FINAL CAPSTONE PYTHON BACKEND!'

@app.route('/rr', methods=['GET', 'POST'])
def method_name():
    return current_user

@app.route('/testLogin', methods=['GET', 'POST'])
# @login_required
def login_test():
    status = jsonify('AUTHORIZED')
    if 'username' in session:
        confirm_login()
        return status
    return jsonify("UNAUTHORIZED", "Username not found")



@app.route('/login_request', methods=['GET'])
@login_required
def check_authorized_user():
    return jsonify('AUTHORIZED')

@app.route('/login_required', methods=['GET'])
def authorized_user():
    return jsonify('UNAUTHORIZED')
    

@app.route('/logout_required', methods=['GET'])
def unauthorized_user():
    return jsonify('UNAUTHORIZED USER', 'LOGGED OUT')




@app.route('/cc', methods=['GET', 'POST'])
def method_new_name():
    if 'username' in session:
        return jsonify('CLOSED TO THE WORLD - ROUTE OPENED TEMP!.........LOGGED IN!')
    return jsonify('CLOSED TO THE WORLD - ROUTE CLOSED!.........YOU ARE NOT LOGGED IN!')




# ************** Add New Article *************

@app.route("/article/add", methods=["POST"])
@login_required
def new_article():
    if request.content_type != "application/json":
        return jsonify("Error creating New Article")
    
    post_data = request.get_json()
    article_meta_data = post_data.get("meta")
    article_content = post_data.get("content")
    user_id = post_data.get("user_id")

    new_article = Article(article_meta_data, article_content, user_id)
    db.session.add(new_article)
    db.session.commit()

    return jsonify(article_schema.dump(new_article))


# ************** Get Articles *************
@app.route("/articles/get")
@login_required
def get_articles():
    all_items = db.session.query(Article).all()
    return jsonify(many_article_schema.dump(all_items))



# ************** Get Single Article *************
@app.route("/article/get/<id>", methods=["GET"])
def get_article(id):
    article = db.session.query(Article).filter(Article.id == id).first()
    return jsonify(article_schema.dump(article))



# ************** Update Article *************
@app.route("/article/update/<id>", methods=["PUT"])
@login_required
def update_article(id):
    if request.content_type != "application/json":
        return jsonify("Error Updating Article")

    update_data = request.get_json()
    article_meta_data = update_data.get("meta")
    article_content = update_data.get("content")

    update_this_article = db.session.query(Article).filter(Article.id == id).first()


    if article_meta_data != None:
        update_this_article.article_meta_data = article_meta_data

    if article_content != None:
        update_this_article.article_content = article_content

    db.session.commit()
    return jsonify(article_schema.dump(update_this_article))




# ************** Delete Article *************
@app.route("/article/remove/<id>", methods=["DELETE"])
@login_required
def delete_article(id):
    delete_article = db.session.query(Article).filter(Article.id == id).first()
    db.session.delete(delete_article)
    db.session.commit()

    return jsonify(f'Article with id: {id} has been deleted')





# ************** Add New Book *************

@app.route("/book/add", methods=["POST"])
@login_required
def new_book():
    if request.content_type != "application/json":
        return jsonify("Error creating New Book")
    
    post_data = request.get_json()
    book_meta_data = post_data.get("meta")
    book_content = post_data.get("content")

    new_material = Book(book_meta_data, book_content)
    db.session.add(new_material)
    db.session.commit()

    return jsonify(book_schema.dump(new_material))


# ************** Get Books *************
@app.route("/books/get")
@login_required
# @login_required
def get_books():
    all_items = db.session.query(Book).all()
    return jsonify(many_book_schema.dump(all_items))






# ************** Add New User *************
@app.route("/users/add", methods=["POST"])
def new_user():
    if request.content_type != "application/json":
        return jsonify("Error creating New User Account")

    post_data = request.get_json()
    username = post_data.get("username")
    password = post_data.get("password")
    email = post_data.get("email")


    pw_hash = bc.generate_password_hash(password).decode('utf-8')

    new_record = User(username, pw_hash, email)
    db.session.add(new_record)
    db.session.commit()

    return jsonify(user_schema.dump(new_record))


# ************** Verification *************
@app.route("/user/auth", methods=["POST"])
def user_verify():
    if request.content_type != 'application/json':
        return jsonify("ERROR submitting info for auth... content_type --> ", request.content_type)

    post_data = request.get_json()
    # username = post_data.get("username")
    email = post_data.get("email")
    password = post_data.get("password")
    remember = True 
    user = db.session.query(User).filter(User.email == email).first()
    user_e = db.session.query(User).filter(User.email == email).first()
    # user_N = db.session.query(User).filter(User.username == username).first()


    if user is None:
        return jsonify("User could not be verified")

    if not bc.check_password_hash(user.password, password):
        return jsonify("Credentials could not be verified")
    # fUser = jsonify(user_schema.dump(User.filter(User.email == email)))
    thisUser = {
        'email': user.email,
        'username': user.username,
        'password': user.password,
        "is_active": user.is_active,
    }
    login_user(user_e, remember=remember)
    confirm_login()
    if login_user(user, remember=True) == True:
        login_user(user, remember=True, duration=timedelta(days=30))
        confirm_login()
        # return thisUser
        return "User Verified!"
    return current_user
    



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You're Now Logged OUT!")
    return redirect('/')



# ************** Get Users *************
@app.route("/users/get")
@login_required
def get_items():
    all_items = db.session.query(User).all()
    return jsonify(many_user_schema.dump(all_items))




if __name__ == '__main__':
    app.run(debug=True)