from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Regexp
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt

app = Flask(__name__)

# --- Security Configurations ---
app.config['SECRET_KEY'] = 'supersecretkey'   # Needed for CSRF + forms
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///firstapp.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secure session cookies
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

# --- Models ---
class FirstApp(db.Model):
    sno = db.Column(db.Integer, primary_key=True, autoincrement=True)
    fname = db.Column(db.String(100), nullable=False)
    lname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"{self.sno} - {self.fname}"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# --- Forms with Validation (Lab: Secure Input Handling) ---
class RegistrationForm(FlaskForm):
    fname = StringField("First Name", validators=[
        DataRequired(),
        Length(min=2, max=50),
        Regexp("^[A-Za-z ]*$", message="Only letters allowed")
    ])
    lname = StringField("Last Name", validators=[
        DataRequired(),
        Length(min=2, max=50),
        Regexp("^[A-Za-z ]*$", message="Only letters allowed")
    ])
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Register")

class ContactForm(FlaskForm):
    name = StringField("Name", validators=[
        DataRequired(),
        Length(min=2, max=50),
        Regexp("^[A-Za-z ]*$", message="Only letters allowed")
    ])
    email = StringField("Email", validators=[DataRequired(), Email()])
    subject = StringField("Subject", validators=[DataRequired(), Length(min=2, max=100)])
    message = TextAreaField("Message", validators=[DataRequired(), Length(min=5, max=500)])
    submit = SubmitField("Send")

class UserForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Register User")

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def hello_world():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Lab: Parameterized Queries via SQLAlchemy ORM (prevents SQL Injection)
        entry = FirstApp(fname=form.fname.data, lname=form.lname.data, email=form.email.data)
        db.session.add(entry)
        db.session.commit()
        flash("Student registered successfully!")
        return redirect(url_for("hello_world"))
    allpeople = FirstApp.query.all()
    return render_template('index.html', form=form, allpeople=allpeople)

@app.route('/delete/<int:sno>')
def delete(sno):
    person = FirstApp.query.filter_by(sno=sno).first_or_404()
    db.session.delete(person)
    db.session.commit()
    flash("Student deleted successfully!")
    return redirect("/")

@app.route('/update/<int:sno>', methods=['GET', 'POST'])
def update(sno):
    person = FirstApp.query.filter_by(sno=sno).first_or_404()
    form = RegistrationForm(obj=person)
    if form.validate_on_submit():
        person.fname = form.fname.data
        person.lname = form.lname.data
        person.email = form.email.data
        db.session.commit()
        flash("Student updated successfully!")
        return redirect("/")
    return render_template('update.html', form=form, allpeople=person)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    submitted = False
    submitted_name = ""
    if form.validate_on_submit():
        submitted = True
        submitted_name = form.name.data  # Fix: capture name before form clears
        flash("Message submitted successfully!")
    return render_template('contact.html', form=form, submitted=submitted, submitted_name=submitted_name)

@app.route('/user_register', methods=['GET', 'POST'])
def user_register():
    form = UserForm()
    if form.validate_on_submit():
        # Lab: Secure Password Storage using bcrypt hashing
        pw_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(email=form.email.data, password=pw_hash)
        db.session.add(new_user)
        db.session.commit()
        flash("User registered securely!")
        return redirect("/")
    return render_template('user_register.html', form=form)

# --- Error Handling (Lab: Secure Error Handling - no info disclosure) ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template("500.html"), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
