from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from dotenv import load_dotenv

import os

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

gravatar = (Gravatar(
                app,
                size=100,
                rating='g',
                default='retro',
                force_default=False,
                force_lower=False,
                use_ssl=False,
                base_url=None)
            )


# TODO: Configure Flask-Login
# init login field
login_manager = LoginManager()
login_manager.init_app(app)

def admin_only(func):
    @wraps(func)
    @login_required # ensure that user is logged in during this operation. If not, unauthorised message will be thrown.
    def wrapper(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)  # not authorised
        else:
            return func(*args, **kwargs)
    return wrapper



# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI")
db = SQLAlchemy(model_class=Base)
db.init_app(app)



# TODO: Create a User table for all your registered users.
class Users(UserMixin, db.Model):
    __tablename__ = "Users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(100), nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)

    posts: Mapped[list["BlogPost"]] = relationship("BlogPost", back_populates="author")
    comments: Mapped[list["Comment"]] = relationship("Comment",back_populates="comment_author")



# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # one-to-many bidirectional dbs User-BlogPost
    author: Mapped["Users"] = relationship(back_populates="posts")
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("Users.id"))

    # one-to-many dbs BlogPost-Comment
    comments: Mapped[list["Comment"]] = relationship(back_populates="parent_post")


    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("Users.id"))
    comment_author = relationship("Users", back_populates="comments")

    # one-to-many dbs BlogPost-Comment
    parent_post: Mapped["BlogPost"] = relationship(back_populates="comments")
    post_id: Mapped[str] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    text: Mapped[str] = mapped_column(Text, nullable=False)



with app.app_context():
    db.create_all()


# invoke login callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(Users, user_id)


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods = ["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        password = register_form.password.data
        hashed_password = generate_password_hash(password, method="scrypt", salt_length=8)

        email = register_form.email.data
        user_check = db.session.execute(db.select(Users).where(Users.email == email)).scalar()

        if user_check:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))


        new_user = Users(
            email = register_form.email.data,
            password = hashed_password,
            name = register_form.name.data,
        )

        db.session.add(new_user)
        db.session.commit()

        # auto-login user after registration
        login_user(new_user)

        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=register_form, logged_in=current_user.is_authenticated)



# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods = ["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        query = db.select(Users).where(Users.email == login_form.email.data)
        user = db.session.execute(query).scalar()
        if user:
            password_check = check_password_hash(user.password, login_form.password.data)
            if password_check:
                login_user(user) # log in the user if credentials are correct.
                return redirect(url_for("get_all_posts"))
            else:
                flash("Password is incorrect. Please try again.")
                return redirect(url_for("login"))
        else:
            flash("The email does not exist, please try again.")
            return redirect(url_for("login"))

    return render_template("login.html", form=login_form, current_user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods = ["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            # if user is auth, add this comment to the db
            new_comment = Comment(
                text=comment_form.comment.data,
                comment_author=current_user,
                parent_post=requested_post
            )

            db.session.add(new_comment)
            db.session.commit()

        else:
            flash("You need to login first, in order to comment on posts.")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html",current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


if __name__ == "__main__":
    app.run(debug=False, port=5002)
