from flask import Flask, render_template, redirect, url_for, flash,request, g, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy.ext.declarative import declarative_base
import os

Base = declarative_base()
login_manager = LoginManager()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///blog.db")

gravatar = Gravatar(app,
                    size=100,
                    rating='d',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None
                    )
##CONNECT TO DB
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager.init_app(app)



##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    author = relationship("User", back_populates='posts')
    comment_relation = relationship('Comment', back_populates='post_relation')

class User(UserMixin, db.Model):
    __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String, nullable=False)
    posts = relationship('BlogPost', back_populates='author')
    comment = relationship('Comment', back_populates='user_relation')

class  Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.String(250), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    post_relation = relationship('BlogPost', back_populates='comment_relation')
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'))
    user_relation = relationship('User', back_populates='comment')

# db.create_all()
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

def logged_in(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('login to see posts')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function()

@app.before_request
def before_request():
    g.user = current_user

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('Email already exist, Please log in')
            return redirect(url_for('login'))
        else:
            new_user = User(name=form.name.data, email=form.email.data, password=generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8))
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['POST','GET'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        log_user = User.query.filter_by(email=form.email.data).first()
        if not log_user:
            flash("The email you entered isn't valid")
            return redirect(url_for('login'))
        elif not check_password_hash(log_user.password, form.password.data):
            flash('Wrong password')
            return redirect(url_for('login'))
        else:
            login_user(log_user)
            return redirect(url_for('get_all_posts'))
    return render_template('login.html', form=form)



@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])

def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    all_comments = Comment.query.all()
    for one in all_comments:
        print(one.comment)
    if request.method == 'POST':
        if current_user.is_authenticated:
            new_comment = Comment(comment=form.comment.data,
                                  user_id=current_user.id,
                                  post_id=post_id
                                  )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash('log in to comment')
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, form=form, comments=all_comments, hash=generate_password_hash(current_user.password, method='pbkdf2:sha256', salt_length=8))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['POST', 'GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if request.method == 'POST':
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
