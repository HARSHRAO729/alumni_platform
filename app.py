\
import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, DateTimeLocalField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "alumni.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ------------- Models -------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="alumni")  # 'admin', 'alumni', 'student'
    # alumni profile fields
    batch = db.Column(db.String(20))
    degree = db.Column(db.String(120))
    branch = db.Column(db.String(120))
    company = db.Column(db.String(120))
    title = db.Column(db.String(120))
    location = db.Column(db.String(120))
    linkedin = db.Column(db.String(200))
    bio = db.Column(db.Text)
    verified = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    start_at = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(200))
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_by = db.relationship("User", backref="events")

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    company = db.Column(db.String(200))
    description = db.Column(db.Text)
    apply_link = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posted_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    posted_by = db.relationship("User", backref="jobs")

class Mentorship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text)
    status = db.Column(db.String(20), default="open")  # open, accepted, closed
    requester_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    mentor_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    requester = db.relationship("User", foreign_keys=[requester_id], backref="mentorship_requests")
    mentor = db.relationship("User", foreign_keys=[mentor_id], backref="mentorship_mentees")

# ------------- Forms -------------
class RegisterForm(FlaskForm):
    full_name = StringField("Full Name", validators=[DataRequired(), Length(min=2, max=120)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    role = SelectField("Role", choices=[("alumni","Alumni"), ("student","Student")])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class ProfileForm(FlaskForm):
    batch = StringField("Batch (e.g., 2019)")
    degree = StringField("Degree")
    branch = StringField("Branch")
    company = StringField("Company")
    title = StringField("Job Title")
    location = StringField("Location")
    linkedin = StringField("LinkedIn URL")
    bio = TextAreaField("Bio")
    submit = SubmitField("Save Profile")

class EventForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    description = TextAreaField("Description")
    start_at = DateTimeLocalField("Starts At", format="%Y-%m-%dT%H:%M", validators=[DataRequired()])
    location = StringField("Location")
    submit = SubmitField("Create Event")

class JobForm(FlaskForm):
    title = StringField("Role", validators=[DataRequired()])
    company = StringField("Company")
    description = TextAreaField("Description")
    apply_link = StringField("Apply Link")
    submit = SubmitField("Post Job")

class MentorshipForm(FlaskForm):
    topic = StringField("Topic", validators=[DataRequired()])
    details = TextAreaField("Details")
    submit = SubmitField("Request Mentorship")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------- Helpers -------------
def admin_required():
    if not current_user.is_authenticated or current_user.role != "admin":
        abort(403)

# ------------- Routes -------------
@app.route("/")
def index():
    events = Event.query.order_by(Event.start_at.asc()).limit(5).all()
    jobs = Job.query.order_by(Job.created_at.desc()).limit(5).all()
    mentors = User.query.filter_by(role="alumni", verified=True).limit(5).all()
    return render_template("index.html", events=events, jobs=jobs, mentors=mentors)

@app.route("/register", methods=["GET","POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))
        user = User(full_name=form.full_name.data, email=form.email.data, role=form.role.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Registered! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        for field in ["batch","degree","branch","company","title","location","linkedin","bio"]:
            setattr(current_user, field, getattr(form, field).data)
        db.session.commit()
        flash("Profile updated!", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html", form=form)

# Events
@app.route("/events")
def events():
    items = Event.query.order_by(Event.start_at.asc()).all()
    return render_template("events.html", items=items)

@app.route("/events/new", methods=["GET","POST"])
@login_required
def events_new():
    form = EventForm()
    if form.validate_on_submit():
        e = Event(title=form.title.data, description=form.description.data, start_at=form.start_at.data,
                  location=form.location.data, created_by=current_user)
        db.session.add(e)
        db.session.commit()
        flash("Event created.", "success")
        return redirect(url_for("events"))
    return render_template("events_new.html", form=form)

# Jobs
@app.route("/jobs")
def jobs():
    items = Job.query.order_by(Job.created_at.desc()).all()
    return render_template("jobs.html", items=items)

@app.route("/jobs/new", methods=["GET","POST"])
@login_required
def jobs_new():
    form = JobForm()
    if form.validate_on_submit():
        j = Job(title=form.title.data, company=form.company.data, description=form.description.data,
                apply_link=form.apply_link.data, posted_by=current_user)
        db.session.add(j)
        db.session.commit()
        flash("Job posted.", "success")
        return redirect(url_for("jobs"))
    return render_template("jobs_new.html", form=form)

# Mentorship
@app.route("/mentorship", methods=["GET","POST"])
@login_required
def mentorship():
    form = MentorshipForm()
    my_requests = Mentorship.query.filter_by(requester_id=current_user.id).all()
    open_requests = Mentorship.query.filter_by(status="open").all()
    if form.validate_on_submit():
        m = Mentorship(topic=form.topic.data, details=form.details.data, requester=current_user)
        db.session.add(m)
        db.session.commit()
        flash("Mentorship request created.", "success")
        return redirect(url_for("mentorship"))
    return render_template("mentorship.html", form=form, my_requests=my_requests, open_requests=open_requests)

@app.route("/mentorship/<int:req_id>/accept")
@login_required
def mentorship_accept(req_id):
    req = Mentorship.query.get_or_404(req_id)
    if req.requester_id == current_user.id:
        flash("You cannot accept your own request.", "warning")
        return redirect(url_for("mentorship"))
    req.mentor = current_user
    req.status = "accepted"
    db.session.commit()
    flash("You are now mentoring on this topic.", "success")
    return redirect(url_for("mentorship"))

# Admin
@app.route("/admin")
@login_required
def admin():
    if current_user.role != "admin":
        abort(403)
    unverified = User.query.filter_by(role="alumni", verified=False).all()
    return render_template("admin.html", unverified=unverified)

@app.route("/admin/verify/<int:user_id>")
@login_required
def admin_verify(user_id):
    if current_user.role != "admin":
        abort(403)
    u = User.query.get_or_404(user_id)
    u.verified = True
    db.session.commit()
    flash(f"Verified {u.full_name}", "success")
    return redirect(url_for("admin"))

# CLI helper
@app.cli.command("initdb")
def initdb():
    db.create_all()
    if not User.query.filter_by(email="admin@demo.com").first():
        admin = User(full_name="Admin", email="admin@demo.com", role="admin", verified=True)
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()
    print("Database initialized. Admin: admin@demo.com / admin123")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email="admin@demo.com").first():
            admin = User(full_name="Admin", email="admin@demo.com", role="admin", verified=True)
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)
