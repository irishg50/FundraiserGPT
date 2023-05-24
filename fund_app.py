# -*- coding: utf-8 -*-
"""
Created on Thu Apr  6 16:41:32 2023

@author: irish
"""


from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask import flash
from flask_migrate import Migrate
from dotenv import load_dotenv
import os
import json
import requests
from requests.exceptions import Timeout
import datetime
import random
import string
from celery import Celery
from celery.result import AsyncResult
import redis
import ssl
from time import sleep

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


@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store'
    return response


@celery.task()
def send_request_to_chatgpt_task(final_prompt, model):
    try:
        response = send_request_to_chatgpt(final_prompt, model)  # Use the desired engine
        return response
    except Exception as e:
        self.retry(exc=e, countdown=120, max_retries=3)


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
    format = db.Column(db.String(25), nullable=False)
    topic = db.Column(db.String(250), nullable=True)
    format = db.Column(db.String(25), nullable=True)
    engine = db.Column(db.String(50), nullable=False)
    chatgpt_response = db.Column(db.Text, nullable=True)
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

            final_output = ""

            if format_row is not None:
                 output = format_row.desc
                 guideline = format_row.guideline
                 final_output = ", The message should be in the form of " + output
                 final_output += ". As much as possible, use the following guidelines for writing the message: " + guideline


            #select the model
            model = request.form["model"]

            full_prompt = final_prompt + " " + final_output

            try:
                task = send_request_to_chatgpt_task.apply_async(args=[full_prompt, model])
                print(f"Task created with ID: {task.id}")
                session['task_id'] = task.id
                session['final_prompt'] = final_prompt
                session['topic'] = topic
                session['model'] = model
                session['format'] = format
                print(f"Task ID stored in session: {session.get('task_id')}")

                task_id = session.get('task_id')

                task = AsyncResult(task_id)
                print("Async Task created")

                return redirect(url_for('submit'))


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
    # Create a list of dictionaries representing each row in the formats table
    format_data = []
    for format_row in formats:
        format_dict = {
            "name": format_row.name,
            "desc": format_row.desc,
            "guideline": format_row.guideline
        }
        format_data.append(format_dict)

    session['format_data'] = format_data

    return render_template("start.html", org_name=current_user.org_name, user_class=current_user.user_class, formats=format_data)

@app.route("/regenerate", methods=["GET", "POST"])
@login_required
def regenerate():
    if request.method == "POST":
        try:
            print("regenerate post started")
            additional_input = request.form["additional_input"]
            print("regenerate form fields 1")
            previous_chat_request = request.form["prev_prompt"]  # Updated variable name
            print("regenerate form fields 2")
            topic = request.form["topic"]
            reqformat = request.form["format"]
            print("regenerate form fields 3")
            model = request.form["model"]
            print("regenerate form fields loaded")
            # Sanitize the input fields
            topic = sanitize_input(topic)
            model = sanitize_input(model)
            additional_input = sanitize_input(additional_input)
            previous_chat_request = sanitize_input(previous_chat_request)
            reqformat = sanitize_input(reqformat)
            print("regenerate form fields sanitized")
            combined_chat_request = previous_chat_request + " In addition, apply the following: " + additional_input

            try:
                print("regenerate send to chatgpt started")
                task = send_request_to_chatgpt_task.apply_async(args=[combined_chat_request, model])
                print(f"Task created with ID: {task.id}")
                session['task_id'] = task.id
                session['final_prompt'] = combined_chat_request
                session['topic'] = topic
                session['model'] = model
                session['format'] = reqformat

                task = AsyncResult(session.get('task_id'))  # Retrieve task_id from session
                print("Async Task created")

                return redirect(url_for("submit"))

            except Exception as e:
                print("Exception:", e)
                return make_response(jsonify({"error": "Internal Server Error1"}), 500)

        except ValueError as ve:
            print("ValueError:", ve)
            return make_response(jsonify({"error": str(ve)}), 400)
        except Exception as e:
            print("Exception:", e)
            return make_response(jsonify({"error": "Internal Server Error2"}), 500)


@app.route("/response")
@login_required
def response():
        task_id = session.get('task_id')
        print(f"Task ID retrieved from session: {task_id}")

        result = celery.AsyncResult(task_id)
        response = result.get()
        chatgpt_response = response["response"]

        # Store the result in the database
        final_prompt = session.get('final_prompt')
        topic = session.get('topic')
        model = session.get('model')
        format = session.get('format')
        chat_request = ChatRequest(user_id=current_user.id, prompt=final_prompt, engine=model, chatgpt_response=chatgpt_response, topic=topic, timestamp=datetime.datetime.utcnow(), format=format)
        db.session.add(chat_request)
        db.session.commit()

        new_chat_request_id = chat_request.id
        print(f"chat_request_id from database: {new_chat_request_id}")
        session['chat_request_id'] = new_chat_request_id

        # Render the template once the task is successful
        return render_template("result.html", response=chatgpt_response, format=format, model=model, topic=topic, final_prompt=final_prompt)


@app.route("/reloadresponse/<int:chat_request_id>")
@login_required
def reloadresponse(chat_request_id):
    chat_request = ChatRequest.query.filter_by(id=chat_request_id).first()

    if chat_request:
        user_id = chat_request.id
        prompt = chat_request.prompt
        model = chat_request.engine
        chatgpt_response = chat_request.chatgpt_response
        topic = chat_request.topic
        format = chat_request.format  # Renamed the variable to format_ to avoid conflict with Python's built-in function


        # Fetch all rows from the Formats table
        formats = Formats.query.all()
        # Create a list of dictionaries representing each row in the formats table
        format_data = []
        for format_row in formats:
            format_dict = {
                "name": format_row.name,
                "desc": format_row.desc,
                "guideline": format_row.guideline
            }
            format_data.append(format_dict)


        # Render the template
        return render_template("result.html", response=chatgpt_response, format=format, formats=format_data, prev_prompt=prompt, model=model, topic=topic)

    return "Chat Request not found"



@app.route('/save_chat_response', methods=['POST'])
@login_required
def save_chat_response():
    data = request.get_json()
    chatgpt_response = data.get('responseValue')

    chatgpt_response_dict = json.loads(chatgpt_response)

    # Access the 'response' value from the dictionary
    chatgpt_response = chatgpt_response_dict['response']


    final_prompt = session.get('final_prompt')
    topic = session.get('topic')
    model = session.get('model')
    format = session.get('format')


    chat_request = ChatRequest(user_id=current_user.id, prompt=final_prompt, engine=model, chatgpt_response=chatgpt_response, topic=topic, timestamp=datetime.datetime.utcnow(), format=format)
    db.session.add(chat_request)
    db.session.commit()

    new_chat_request_id = chat_request.id
    print(f"chat_request_id from database: {new_chat_request_id}")
    session['chat_request_id'] = new_chat_request_id
    flash("Chat request ID stored in session.")

    return jsonify({"chat_request_id": new_chat_request_id})

@app.route('/api/tasks/<task_id>', methods=['GET'])
def get_task_status(task_id):
    # Retrieve the task status or result using the provided task_id
    task_result = AsyncResult(task_id)

    # Check if the task_result exists
    if task_result is not None:
        # Task is completed, return the result

        if isinstance(task_result, AsyncResult):
            # Extract relevant information from AsyncResult and convert it to a dictionary
            result_dict = {
                'task_id': task_id,
                'status': task_result.status,
                'result': task_result.result,
                # Add any other relevant information from the AsyncResult object
            }

            # Return the dictionary as a JSON response
            return jsonify(result_dict)

    else:
        # Task is still in progress or does not exist
        return jsonify({'status': 'PENDING'})


@app.route("/result")
@login_required
def result(chat_request_id):
    chat_request_id = session.get("chat_request_id")
    print(f"chat_request_id from session: {chat_request_id}")

#    current_record_id = request.args.get('current_record_id', None)
#    if current_record_id is not None:
#        chat_request_id = int(current_record_id)

    chat_request = ChatRequest.query.get(chat_request_id)
    if chat_request:
        print("Database data returned")
        # Store the necessary parameters in the session
        chatgpt_response = chat_request.chatgpt_response
        format = chat_request.format

        # Create a list of dictionaries representing each row in the formats table
        formats = Formats.query.all()
        format_data = []
        for format_row in formats:
            format_dict = {
                "name": format_row.name,
                "desc": format_row.desc,
                "guideline": format_row.guideline
            }
            format_data.append(format_dict)
        print("formats retrieved")

        return render_template("result.html", response = chatgpt_response, format = format, formats = formats)


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


@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    if request.method == 'POST':
        # Process the POST request data here
        # Example: Get data from the form
        form_data = request.form['form_field']
        # Process the data as needed

        # Redirect or return a response

    # Handle the GET request
    task_id = session.get('task_id')
    return render_template("submit.html", task_id=task_id)

@app.route('/status')
@login_required
def taskstatus():

    task_id = session.get('task_id')
    print(f"Task ID retrieved from session: {task_id}")
    task = send_request_to_chatgpt_task.AsyncResult(task_id)

    while task.state not in ['SUCCESS', 'FAILURE']:
        print(f"Task state is: {task.state}")
        # Wait for a short interval before checking the task status again
        sleep(3)

    if task.state == 'SUCCESS':
        return redirect(url_for('response'))

    # If the task fails, you can redirect or render an error template
    if task.state == 'FAILURE':
        response = {
            'state': task.state,
            'status': str(task.info),  # this is the result you updated from `send_request_to_chatgpt_task`
        }
        return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True)
