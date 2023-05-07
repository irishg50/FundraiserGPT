# -*- coding: utf-8 -*-
"""
Created on Thu Apr  6 16:41:32 2023

@author: irish
"""


from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from dotenv import load_dotenv
import os
import requests
import datetime
import random
import string

load_dotenv()


OPENAI_KEY = os.environ.get("OPENAI_KEY")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

DATABASE_URL = os.environ.get('DATABASE_URL')
#DATABASE_URL = "postgresql://postgres:POST50pat!@localhost:5432/fund_app_db"

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

    def __repr__(self):
        return f"<User {self.username}>"

class ChatRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    prompt = db.Column(db.Text, nullable=False)
    topic = db.Column(db.String(250), nullable=True)
    engine = db.Column(db.String(50), nullable=False)
    chatgpt_response = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"<ChatRequest {self.prompt}>"



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
        "max_tokens": 2150,
    }

    print("Headers:", headers)
    print("Data:", data)

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

@app.route("/chat_history")
@login_required
def chat_history():
    # Check if the current user's ID is greater than 6
    if int(current_user.user_class) > 6:
        # If true, retrieve all records from the ChatRequest table
        chat_requests = ChatRequest.query.all()
    else:
        # Otherwise, retrieve only the records that match the current user's ID
        chat_requests = ChatRequest.query.filter_by(user_id=current_user.id).all()
    # Render the 'chat_history.html' template and pass the 'chat_requests' variable to it
    return render_template("chat_history.html", chat_requests=chat_requests)

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
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
        return redirect(url_for("index"))

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
            login_user(user)
            return redirect(url_for("index"))

        # Log the result of the password check
        app.logger.info("Invalid username or password")
        flash("Invalid username or password")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
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
            #final_prompt = f"{prompt} Topic: {topic}. Audience: {audience}. Notes: {notes}. Urgency: {urgency}. Format: {format}."

            #build the content prompt from the form input
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

            # add format and fundraising guidelines
             
            output = ""
            guidelines = ""
            
            if format == "Email":
                output = "an email message of between 6-10 paragraphs"                        
                guidelines = "1) write an attention-grabbing opener at the start 2) Focus on the impact of the organization's work 3) Include a compeling story  4) have a strong call-to-action  5) include a post-script that reinforces the main call-to-action. Please list at bottom all source references for documents quoted or cited."

            if format == "Facebook":
                output = "a post suitable for Facebook of no more than 1000 characters."                        
                guidelines = "1) the message should begin with an attention-getting headline 2) do not use 'Dear' or any other salutation at the start of the message  2) Include a description of a suitable image at the bottom 3) have a strong call-to-action 4) include several hashtags related to the message content. Please list at bottom all source references for documents quoted or cited."
     
            if format == "Twitter":
                output = "3 unique tweets or not more than more than 400 characters each."                        
                guidelines = "1) Include emojis if possible 2) have e a strong call-to-action 3) include several hashtags relatedto the message content. Please list at bottom all source references for documents quoted or cited."
         
            if format == "DonationForm":
                output = "Copy for a donation form for no more than 5 paragraphs."                        
                guidelines = "1) Express appreciation for the decision to make a donation 2) Reinforce the message of the importance of making a donations 3) Describe briefly how donations are used to further it impact of the organization's work. 4) do not use 'Dear' or any other salutation at the start of the message 2) do not use 'Sincerely' or any other signpff at the end of the message.   Please list at bottom all source references for documents quoted or cited."

            if format == "Letter":
                output = "A personalized printed letter of at least 15 paragraphs, but no more than 25 paragraphs."                        
                guidelines = "1) write an attention-grabbing opener at the start 2) Focus on the impact of the organization's work 3) Include a compeling story  4) have a strong call-to-action  5) include a post-script that reinforces the main call-to-action. Please list at bottom all source references for documents quoted or cited."
    
    
            final_prompt += ", The message should be in the form of " + output
            final_prompt += ". As much as possible, use the following guidelines for writing the message: " + guidelines

            #select the model
            model = request.form["model"]


            response = send_request_to_chatgpt(final_prompt, model)  # Use the desired engine
            if response["success"]:
                chat_request = ChatRequest(user_id=current_user.id, prompt=final_prompt, engine="gpt-3.5-turbo", chatgpt_response=response["response"], topic=topic, timestamp=datetime.datetime.utcnow())
                db.session.add(chat_request)
                db.session.commit()
                return jsonify(response)
            else:
                print("Error from send_request_to_chatgpt:", response["error"])
                return make_response(jsonify({"error": response["error"]}), 400)
        except ValueError as ve:
            print("ValueError:", ve)
            return make_response(jsonify({"error": str(ve)}), 400)
        except Exception as e:
            print("Exception:", e)
            return make_response(jsonify({"error": "Internal Server Error"}), 500)

    return render_template("index.html", org_name=current_user.org_name, user_class=current_user.user_class)



if __name__ == "__main__":
    app.run(debug=True)
