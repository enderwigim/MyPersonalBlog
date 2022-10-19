from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap4
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import exc, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, Comment
from flask_gravatar import Gravatar
import bleach
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap4(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES
Base = declarative_base()


class Users(db.Model, Base, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    # BlogPost Table Parenting
    posts = db.relationship('BlogPost', back_populates="author")
    # Comments Table Parenting
    comments = db.relationship('Comments', back_populates="comment_author")


class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # Users Table Parenting
    author = db.relationship('Users', back_populates="posts")
    author_id = db.Column(db.Integer, ForeignKey('user.id'))
    # Comments Table Parenting
    comments_post = db.relationship('Comments', back_populates="parent_post")


class Comments(db.Model, Base, UserMixin):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # Users Table Parenting
    comment_author = db.relationship('Users', back_populates="comments")
    comment_author_id = db.Column(db.Integer, ForeignKey('user.id'))
    # BlogPost Table Parenting
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    parent_post = relationship('BlogPost', back_populates="comments_post")
    text = db.Column(db.String(250), nullable=False, unique=False)


# Use this the first time. Just to create the DB
# with app.app_context():
    # db.create_all()
# This function creates an admin by default, you must use it when you are creating the DB
# create_admin()

# LOG IN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Gravatar
gravatar = Gravatar(app,
                    size=80,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# SOME FUNCTIONS
# Admin only decorator function
def admin_only(function):
    """
    Decorator, blocks users that are not logged in or are not the admin
    """

    def wrapper_function(*args, **kwargs):
        if not current_user.is_authenticated and current_user.id != 1:
            return abort(403)
        else:
            return function(*args, **kwargs)

    return wrapper_function


def clean_invalid_html(html_input):
    """
    Sanitize possible dangerous HTML inputs
    """
    allowed_tags = ['a', 'abbr', 'acronym', 'address', 'b', 'br', 'div', 'dl', 'dt',
                    'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img',
                    'li', 'ol', 'p', 'pre', 'q', 's', 'small', 'strike',
                    'span', 'sub', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th',
                    'thead', 'tr', 'tt', 'u', 'ul'
                    ]

    allowed_attrs = {
        'a': ['href', 'target', 'title'],
        'img': ['src', 'alt', 'width', 'height'],
    }
    html_cleaned = bleach.clean(text=html_input,
                                attributes=allowed_attrs,
                                tags=allowed_tags)
    return html_cleaned


def create_admin():
    """
    Creates an admin
    """
    admin = Users(email="admin@gmail.com",
                  name="Admin",
                  paswword="admin")
    db.session.add(admin)
    db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    if current_user.is_authenticated:
        user_id = int(current_user.get_id())
    else:
        user_id = 0
    return render_template("index.html", all_posts=posts, user_id=user_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        password = generate_password_hash(password=form.password.data,
                                          method='pbkdf2:sha256',
                                          salt_length=8)
        new_user = Users(
            email=form.email.data,
            password=password,
            name=form.name.data,
        )
        db.session.add(new_user)
        # If the email is in the DB, The user will be redirected to the login route with a flash message that tells
        # him to log in.
        try:
            db.session.commit()
        except exc.IntegrityError:
            flash("You've already signed up with that mail. Log in instead")
            return redirect(url_for('login'))
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login',  methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        email = form.email.data
        password = form.password.data
        user = Users.query.filter_by(email=email).first()
        if user and check_password_hash(pwhash=user.password, password=password):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        else:
            flash('Invalid email or password.')
        return render_template('login.html', form=form)
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = Comment()
    if current_user.is_authenticated:
        user_id = int(current_user.get_id())
    else:
        user_id = 0
    requested_post = BlogPost.query.filter_by(id=post_id).first()
    # In this section, the user will be available to create a comment
    if request.method == 'POST':
        if current_user.is_authenticated:
            new_comment = Comments(text=clean_invalid_html(request.form.get('body')),
                                   comment_author_id=current_user.id,
                                   post_id=post_id
                                   )
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash('You need to Log in to comment')
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, user_id=user_id, comment_form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def create_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
            author_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
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
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete/<int:post>/<int:comment_id>")
def delete_comment(post, comment_id):
    """
    Deletes from DB an unwanted comment
    """
    comment_to_delete = Comments.query.get(comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post))


if __name__ == "__main__":
    app.run(debug=True)
    # app.run(host='0.0.0.0', port=5000)
