# -*- coding: utf-8 -*-
"""
Created on Thu Apr  6 16:41:32 2023

@author: irish
"""


from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from dotenv import load_dotenv
import os
import requests
from requests.exceptions import Timeout
import datetime
import random
import string
from celery import Celery
import redis
import ssl

load_dotenv()


OPENAI_KEY = os.environ.get("OPENAI_KEY")


def make_celery(app):
    celery = Celery(
        app.import_name,
        backend=app.config['result_backend'],
        broker=app.config['broker_url']
    )
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery


app = Flask(__name__)
app.config.update(
    broker_url='rediss://:p952ada0b5ae194c7c49dd484e19814e03c9a324296ecfcfe8ff1ae4aca4ebc2e@ec2-3-234-14-83.compute-1.amazonaws.com:14850?ssl_cert_reqs=CERT_NONE',
    result_backend='rediss://:p952ada0b5ae194c7c49dd484e19814e03c9a324296ecfcfe8ff1ae4aca4ebc2e@ec2-3-234-14-83.compute-1.amazonaws.com:14850?ssl_cert_reqs=CERT_NONE'
)

celery = make_celery(app)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
DATABASE_URL = os.environ.get('DATABASE_URL')
#DATABASE_URL = "postgresql://irish:POST50pat!@localhost:5432/fund_app_db"

if DATABASE_URL is None:
    raise ValueError("DATABASE_URL environment variable is not set")
elif DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
    
db = SQLAlchemy(app)

migrate = Migrate(app, db)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


@celery.task(bind=True)
def send_request_to_chatgpt_task(self, final_prompt, model):
    try:
        response = send_request_to_chatgpt(final_prompt, model)  # Use the desired engine
        return response
    except Exception as e:
        self.retry(exc=e, countdown=60, max_retries=3)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(12), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    org_name = db.Column(db.String(120), nullable=False) 
    fund_mission = db.Column(db.String(250), nullable=True)
    password = db.Column(db.String(128), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    user_status = db.Column(db.String(25), nullable=True)
    user_class = db.Column(db.Integer, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<User {self.username}>"

class ChatRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship('User', backref='chat_requests') 
    prompt = db.Column(db.Text, nullable=False)
    topic = db.Column(db.String(250), nullable=True)
    engine = db.Column(db.String(50), nullable=False)
    chatgpt_response = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"<ChatRequest {self.prompt}>"


class Formats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(25), nullable=False)
    desc = db.Column(db.String(100), nullable=False) 
    guideline =db.Column(db.String(500), nullable=False)



def sanitize_input(text):
    return text.strip().replace("'", "")

def send_request_to_chatgpt(prompt, engine):
    if not prompt or not engine:
        raise ValueError("Prompt and engine fields are required.")

    valid_engines = ["gpt-4", "gpt-3.5-turbo"]

    if engine not in valid_engines:
        raise ValueError("Invalid engine selection.")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENAI_KEY}",
    }

    data = {
        "messages": [{"role": "system", "content": "You are a helpful assistant."}, {"role": "user", "content": prompt}],
        "model": engine,
        "temperature": 0.5,
        "max_tokens": 3500,
    }

    response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data)

    if response.status_code == 200:
        chatgpt_response = response.json()
        message = chatgpt_response["choices"][0]["message"]["content"]
        return {"success": True, "response": message}
    else:
        return {"success": False, "error": response.text}

def generate_unique_user_id():
    # Generate a random alphanumeric string of length 12
    user_id = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    # Check if the generated user_id already exists in the database
    while User.query.filter_by(user_id=user_id).first():
        # If it exists, generate a new one
        user_id = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    return user_id

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/chat_history")
@login_required
def chat_history():
    # Check if the current user's ID is greater than 6
    if int(current_user.user_class) > 6:
        # If true, retrieve all records from the ChatRequest table
        chat_requests = ChatRequest.query.order_by(ChatRequest.timestamp.desc()).all()
    else:
        # Otherwise, retrieve only the records that match the current user's ID
        chat_requests = ChatRequest.query.filter_by(user_id=current_user.id).order_by(ChatRequest.timestamp.desc()).all()
    # Render the 'chat_history.html' template and pass the 'chat_requests' variable to it
    return render_template("chat_history.html", chat_requests=chat_requests)

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        if int(current_user.user_class) < 7:
            return redirect(url_for("index"))


    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        org_name = request.form["org_name"]
        fund_mission = request.form["fund_mission"]  
        password = request.form["password"]

        # Generate a unique user_id
        user_id = generate_unique_user_id()

        # Check for duplicate username
        if User.query.filter_by(username=username).first():
            flash("Username is already taken.")
            return redirect(url_for("register"))

        # Check for duplicate email address
        if User.query.filter_by(email=email).first():
            flash("Email address is already in use.")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        user = User(
            user_id=user_id,  # Assign the generated user_id
            username=username,
            email=email,
            org_name=org_name,
            fund_mission=fund_mission,
            password=hashed_password,
            registered_on=datetime.datetime.utcnow(),
            user_status="active",
            user_class=3 
        )
        db.session.add(user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("start"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Log the received username and password
        app.logger.info(f"Received username: {username}")
        app.logger.info(f"Received password: {password}")

        user = User.query.filter_by(username=username).first()

        # Log the result of the database query
        if user:
            app.logger.info(f"User found in database: {user.username}")
        else:
            app.logger.info("User not found in database")

        if user and bcrypt.check_password_hash(user.password, password) and user.user_status == "active":
            user.last_login = datetime.datetime.utcnow()  # update last_login
            db.session.commit()
            login_user(user)
            return redirect(url_for("start"))

        # Log the result of the password check
        app.logger.info("Invalid username or password")
        flash("Invalid username or password")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/start", methods=["GET", "POST"])
@login_required
def start():
    if request.method == "POST":
        try:
            org_name = request.form["org_name"]
            topic = request.form["topic"]
            audience = request.form["audience"]
            notes = request.form["notes"]
            urgency = request.form["urgency"]
            impact = request.form["impact"]
            format = request.form["format"]

            # Sanitize the input fields
            topic = sanitize_input(topic)
            audience = sanitize_input(audience)
            notes = sanitize_input(notes)
            urgency = sanitize_input(urgency)
            impact = sanitize_input(impact)
            format = sanitize_input(format)

            # Concatenate the fields to create the final prompt
            final_prompt = "You are a helpful fundraising copy writer, helping to prepare fundraising content for " + org_name + "."
            final_prompt += " The message should have an overall tone of " + "earnest and urgent" 
            if audience :
                final_prompt += ", and be targeted to " + audience
            final_prompt += ". The topic of the message should be " + topic 
            if urgency :
                final_prompt += " with an urgency because of " + urgency
            if impact :
                final_prompt += ". Donations will support the organisation's important work to " + impact 
            if notes :
                final_prompt += ". Also the consider the following points when crafting the message: " + notes

            format_row = Formats.query.filter_by(name=format).first()

            if format_row is not None:
                 output = format_row.desc
                 guideline = format_row.guideline
                 final_prompt += ", The message should be in the form of " + output
                 final_prompt += ". As much as possible, use the following guidelines for writing the message: " + guideline

            #select the model
            model = request.form["model"]

            try:
                task = send_request_to_chatgpt_task.apply_async(args=[final_prompt, model])
                print(f"Task created with ID: {task.id}")
                session['task_id'] = task.id
                session['final_prompt'] = final_prompt
                session['topic'] = topic
                session['model'] = model
                print(f"Task ID stored in session: {session.get('task_id')}")
                return redirect(url_for('taskstatus'))            

            except Exception as e:
                print("Exception:", e)
                return make_response(jsonify({"error": "Internal Server Error1"}), 500)

        except ValueError as ve:
            print("ValueError:", ve)
            return make_response(jsonify({"error": str(ve)}), 400)
        except Exception as e:
            print("Exception:", e)
            return make_response(jsonify({"error": "Internal Server Error2"}), 500)

    # Fetch all rows from the Formats table
    formats = Formats.query.all()

    return render_template("start.html", org_name=current_user.org_name, user_class=current_user.user_class, formats=formats)

@app.route("/continue_conversation", methods=["POST"])
@login_required
def continue_conversation():
    additional_input = request.form["additional_input"]
    previous_chat_request = request.form["chat_request"]
    topic = request.form["topic"]
    model = request.form["model"]
    combined_chat_request = previous_chat_request + " In addition, apply the following: " + additional_input
    model = "gpt-3.5-turbo"  # Use the desired engine

    try:
        response = send_request_to_chatgpt(combined_chat_request, model)
    except Timeout:
        flash("The request to the ChatGPT service timed out. Please try again.")
        return redirect(url_for("response"))    

    if response["success"]:
        chat_request = ChatRequest(user_id=current_user.id, prompt=combined_chat_request, engine=model, chatgpt_response=response["response"], topic=topic, timestamp=datetime.datetime.utcnow())
        db.session.add(chat_request)
        db.session.commit()
        session['chat_request'] = combined_chat_request  # Update chat_request in session
        return redirect(url_for("response", chatgpt_response=response["response"]))
    else:
        print("Error from send_request_to_chatgpt:", response["error"])
        return make_response(jsonify({"error": response["error"]}), 400)

@app.route("/reload_response/<int:chat_request_id>")
@login_required
def reload_response(chat_request_id):
    # Retrieve the ChatRequest record based on the provided id
    chat_request = ChatRequest.query.get(chat_request_id)
    if chat_request:
        # Store the necessary parameters in the session
        session['chat_request'] = chat_request.prompt
        session['chatgpt_response'] = chat_request.chatgpt_response
        session['topic'] = chat_request.topic
        session['model'] = chat_request.engine
        # Redirect to the response route
        return redirect(url_for("response"))
    else:
        flash("Chat request not found.")
        return redirect(url_for("chat_history"))

@app.route("/response")
@login_required
def response():
    chatgpt_response = ""
    task_id = session.get('task_id')
    task = send_request_to_chatgpt_task.AsyncResult(task_id)

    if task.state == 'SUCCESS':
        response = task.get()
        chatgpt_response = response["response"]

        # Store the result in the database
        final_prompt = session.get('final_prompt')
        topic = session.get('topic')
        model = session.get('model') 
        chat_request = ChatRequest(user_id=current_user.id, prompt=final_prompt, engine="gpt-3.5-turbo", chatgpt_response=chatgpt_response, topic=topic, timestamp=datetime.datetime.utcnow())
        db.session.add(chat_request)
        db.session.commit()

        # Store variables in session
        session['chatgpt_response'] = chatgpt_response

    return render_template("response.html", response=chatgpt_response, chat_request=chat_request, topic=topic, model=model)


@app.route("/admin")
@login_required
def admin():
    if current_user.user_class > 6:
        users = db.session.query(
            User,
            db.func.count(ChatRequest.id).label('chat_request_count')
        ).outerjoin(
            ChatRequest, User.id == ChatRequest.user_id
        ).group_by(User.id).order_by(User.last_login.desc()).all()

        return render_template("admin.html", users=users)
    else:
        flash("You do not have permission to access this page.")
        return redirect(url_for("index"))

@app.route('/status')
@login_required
def taskstatus():
    task_id = session.get('task_id')
    print(f"Task ID retrieved from session: {task_id}")
    task = send_request_to_chatgpt_task.AsyncResult(task_id)
    if task.state == 'PENDING':
        response = {
            }
    elif task.state == 'SUCCESS':
        response = {
            'state': task.state,
            'status': 'Task completed successfully',
            'result': task.result
        }
    elif task.state != 'FAILURE':
        response = {
            'state': task.state,
            'status': str(task.info),  # this is the result you returned from `send_request_to_chatgpt_task`
        }
        if 'result' in task.info:
            response['result'] = task.info['result']
    else:
        # something went wrong in the background job
        response = {
            'state': task.state,
            'status': str(task.info),  # this is the exception raised
        }
    return jsonify(response)




if __name__ == "__main__":
    app.run(debug=True)
