from models import db, Mood, User, Feedback, Poll, Explanation, Tracking, ClassSession, ClassSessionStudents,  Reason, Mood
from werkzeug.exceptions import BadRequest, NotFound, InternalServerError, Unauthorized
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from flask import (jsonify, request, redirect, url_for, session, Blueprint, Response,
                   current_app, url_for)

import pdb

from datetime import datetime, timedelta
from io import StringIO
from extensions import bcrypt
import os
import uuid
from uuid import uuid4

import traceback
import logging
import random
import string
from flask_cors import cross_origin
from sqlalchemy import func



# Set the logging level to DEBUG
logging.basicConfig(level=logging.DEBUG)


# Create blueprints
auth_blueprint = Blueprint("auth", __name__)
mood_blueprint = Blueprint("mood", __name__)
insights_blueprint = Blueprint("insights", __name__)
class_session_blueprint = Blueprint("class_session", __name__)


# Function to generate a random session code
def generate_session_code():
    # Generate a random string of alphanumeric characters
    code_length = 6  # You can adjust the length of the session code
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(code_length))


# Class session routes
@class_session_blueprint.route("/class-session/create", methods=["POST"])
@jwt_required()
def create_class_session():
    """
    Create Class Session
    ---
    tags:
      - Class Session
    parameters:
      - name: teacher_id
        in: formData
        type: string
        required: true
    responses:
      201:
        description: Class session created successfully
      400:
        description: Missing required information or invalid input
      401:
        description: Unauthorized access
      500:
        description: Internal Server Error
    """
    try:
        current_username = get_jwt_identity()

        # Get the user by username
        user = User.query.filter_by(username=current_username).first()
        if not user or user.role != "teacher":
            raise Unauthorized("Only teachers can create class sessions")
        
        if not current_username:
            raise BadRequest("Missing required information: 'current_username'")


        
        
        session_name = request.json.get("session_name")
        if not session_name:
            raise BadRequest("Missing required information: 'session_name'")

        # Generate a random 6-character session code
        session_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

        # Create a new class session
        new_class_session = ClassSession(code=session_code, teacher_id=user.id, session_name=session_name)
        db.session.add(new_class_session)
        db.session.commit()

        return jsonify({"message": "Class session created successfully", "session_id": new_class_session.id, "session_code" : new_class_session.code}), 201
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Unauthorized as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    


# Add a new route for fetching class sessions
@class_session_blueprint.route("/class-sessions/list", methods=["GET"])
@jwt_required()
def get_class_sessions():
    try:
        current_username = get_jwt_identity()

        # Get the user by username
        user = User.query.filter_by(username=current_username).first()
        if not user or user.role != "teacher":
            raise Unauthorized("Only teachers can fetch class sessions")

        # Fetch class sessions based on the user (teacher)
        class_sessions = ClassSession.query.filter_by(teacher_id=user.id).all()

        # Convert class sessions to a list of dictionaries
        class_sessions_data = [
            {
                "session_id": session.id,
                "session_code": session.code,
                "session_name": session.session_name,
                "created_at": session.created_at.strftime('%Y-%m-%d %H:%M:%S')
                
            }
            for session in class_sessions
        ]

        return jsonify({"class_sessions": class_sessions_data}), 200
    except Unauthorized as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    


@class_session_blueprint.route("/class-sessions/<int:session_id>", methods=["GET"])
@jwt_required()
def get_class_session(session_id):
    try:
        current_username = get_jwt_identity()

        # Get the user by username
        user = User.query.filter_by(username=current_username).first()
        if not user or user.role != "teacher":
            raise Unauthorized("Only teachers can fetch class sessions")

        # Fetch the class session based on the session ID and teacher ID
        class_session = ClassSession.query.filter_by(id=session_id, teacher_id=user.id).first()

        if not class_session:
            return jsonify({"error": "Class session not found"}), 404

        # Count the number of students enrolled in the class session
        num_students = db.session.query(func.count(ClassSessionStudents.user_id)).filter_by(class_session_id=session_id).scalar()

        # Convert class session to a dictionary
        class_session_data = {
            "id": class_session.id,
            "code": class_session.code,
            "teacher_id": class_session.teacher_id,
            "session_name": class_session.session_name,
            "created_at": class_session.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "num_students": num_students
        }

        return jsonify(class_session_data), 200
    except Unauthorized as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500





# Authentication routes
@auth_blueprint.route("/auth/register", methods=["POST"])
def register_user():
    """
    User Registration
    ---
    tags:
      - Authentication
    parameters:
      - name: username
        in: formData
        type: string
        required: true
      - name: password
        in: formData
        type: string
        required: true
      - name: email
        in: formData
        type: string
        required: true
      - name: name
        in: formData
        type: string
        required: true
      - name: age
        in: formData
        type: integer
        required: true
    responses:
      201:
        description: User registration successful
      400:
        description: Missing required information or invalid input
    """

    try:
        username = request.json.get("username")
        password = request.json.get("password")
        email = request.json.get("email")
        name = request.json.get("name")
        age = request.json.get("age")

        # Validate input
        if not username or not password or not email or not name or not age:
            raise BadRequest("Missing required information")

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            raise BadRequest("Username already exists")
        
        role = request.json.get("role", "teacher")

        # Create new user
        new_user = User(username=username, password=bcrypt.generate_password_hash(password).decode("utf-8"), email=email, name=name, age=age, is_active=True, role=role)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "User registration successful"}), 201
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        print("An unexpected error occurred:", e)
        traceback.print_exc()  # This will print the traceback
        return jsonify({"error": "An unexpected error occurred"}), 500


@auth_blueprint.route("/auth/login", methods=["POST"])
def login_user():
    """
    User Login
    ---
    tags:
      - Authentication
    parameters:
      - name: username (optional)
        in: formData
        type: string
      - name: password (optional)
        in: formData
        type: string
      - name: session_token (optional)
        in: formData
        type: string
    responses:
      200:
        description: User logged in successfully
      400:
        description: Missing required information or invalid input
      401:
        description: Invalid username or password or session token
    """
    try:
        username = request.json.get("username")
        password = request.json.get("password")
        session_token = request.json.get("session_token")

        # Validate input
        if not (username and password) and not session_token:
            raise BadRequest("Missing required information")

        # Check if user exists and password is valid (if username provided)
        if username and password:
            user = User.query.filter_by(username=username).first()
            if not user or not bcrypt.check_password_hash(user.password, password):
                raise Unauthorized("Invalid username or password")

        # Check if session token is valid (if provided)
        elif session_token:
            # Implement logic to validate session token (e.g., check against stored tokens)
            if not validate_session_token(session_token):
                raise Unauthorized("Invalid session token")
            # Retrieve user associated with the token

        # Create access token for authenticated users (not anonymous)
        if not user.is_anonymous:
            access_token = create_access_token(identity=user.username, additional_claims={"role": user.role}, expires_delta=timedelta(days=1))
            return jsonify({"access_token": access_token}), 200

        # Use a different token type or mechanism for anonymous access
        # (e.g., session token instead of JWT)
        else:
            return jsonify({"session_token": session_token}), 200

    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Unauthorized as e:
        return jsonify({"error": str(e)}), 401



@auth_blueprint.route("/auth/register_anonymous", methods=["POST"])
def anonymous_login():
    """
    Anonymous User Registration
    ---
    tags:
      - Authentication
    parameters:
      - name: code
        in: formData
        type: string
        required: true
        description: The code provided by the teacher
    responses:
      201:
        description: Anonymous user registered and logged in successfully
      400:
        description: Invalid code or missing information
      500:
        description: Internal Server Error
    """
    try:
        # Validate input
        code = request.json.get("code")
        if not code:
            raise BadRequest("Missing code")

        # Check if the code is valid and get the associated class session
        class_session = get_class_session_by_code(code)
        if not class_session:
            raise BadRequest("Invalid code")

        # Generate a unique anonymous username
        username = f"anonymous_{uuid4()}"

        # Create new user with is_anonymous flag set to True
        new_user = User(username=username, is_anonymous=True)
        db.session.add(new_user)
        db.session.commit()

        # Associate the user with the class session
        class_session.students.append(new_user)
        db.session.commit()

        # Use a different token type or mechanism for anonymous access
        # (e.g., session token instead of JWT)
        session_token = f"{uuid4().hex}-{class_session.id}"

        return jsonify({"session_token": session_token}), 201
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred"}), 500

# You need to implement the code verification logic based on your requirements
def get_class_session_by_code(code):
    # Implement your code verification logic here
    # For example, query the database to get the class session associated with the code
    return ClassSession.query.filter_by(code=code).first()

@auth_blueprint.route("/auth/logout", methods=["DELETE"])
@jwt_required()
def logout_user():
    """
    User Logout
    ---
    tags:
      - Authentication
    responses:
      200:
        description: User logged out successfully
      401:
        description: Unauthorized
    """
    jti = get_jwt_identity()
    return jsonify({"message": "User logged out successfully"}), 200


# Individual Tracking API
@insights_blueprint.route("/insights/individual-tracking", methods=["GET"])
@jwt_required()
def individual_tracking():
    """
    Individual Tracking
    ---
    tags:
      - Insights
    responses:
      200:
        description: Individual tracking data retrieved successfully
    """
    user_role = get_jwt_identity()["role"]
    if user_role != "teacher":
        return jsonify({"error": "Unauthorized access"}), 403
    try:
        # Retrieve mood data (e.g., for the past 30 days)
        recent_moods = Mood.query.filter(Mood.timestamp > (db.func.now() - timedelta(days=30))).all()
        mood_data = [{"mood": mood.mood, "timestamp": mood.timestamp.strftime("%Y-%m-%d %H:%M:%S")} for mood in recent_moods]

        return jsonify({"data": mood_data}), 200
    except Exception as e:
        logging.exception("An error occurred:")
        return jsonify({"error": "Internal Server Error"}), 500

# Mood Analysis API
@insights_blueprint.route("/insights/mood-analysis", methods=["GET"])
def mood_analysis():
    """
    Mood Analysis
    ---
    tags:
      - Insights
    responses:
      200:
        description: Mood analysis data retrieved successfully
    """
    try:
        # Retrieve mood data (e.g., for the past 30 days)
        recent_moods = Mood.query.filter(Mood.timestamp > (db.func.now() - timedelta(days=30))).all()
        mood_data = [{"mood": mood.mood, "timestamp": mood.timestamp.strftime("%Y-%m-%d %H:%M:%S")} for mood in recent_moods]

        return jsonify({"data": mood_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Anonymous Feedback API
@insights_blueprint.route("/insights/anonymous-feedback", methods=["POST"])
def anonymous_feedback():
    """
    Anonymous Feedback
    ---
    tags:
      - Insights
    parameters:
      - name: feedback
        in: formData
        type: string
        required: true
    responses:
      201:
        description: Anonymous feedback submitted successfully
      400:
        description: Invalid feedback input
    """
    try:
        feedback = request.get_json().get("feedback")

        # Validate feedback input (optional)
        if not feedback or not isinstance(feedback, str):
            raise BadRequest("Invalid feedback input")
        
       

        # Store feedback data in the database
        timestamp = datetime.utcnow()

        print("Timestamp before insertion:", timestamp)

        

        new_feedback = Feedback( user_id=None, feedback=feedback, timestamp= timestamp)
        db.session.add(new_feedback)
        db.session.commit()

        print("Timestamp after insertion:", new_feedback.timestamp)


        return jsonify({"message": "Anonymous feedback submitted successfully"}), 201
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        error_message = f"Error: {str(e)}. Timestamp: {timestamp}"
        return jsonify({"error": error_message}), 500



# Class Climate API
#This shows class climate for the past 30 days
# This shows class climate for the past 30 days
@insights_blueprint.route("/insights/class-climate", methods=["GET"])
def class_climate():
    """
    Class Climate
    ---
    tags:
      - Insights
    parameters:
      - name: class_session_id
        in: query
        type: string
        required: true
        description: The ID of the class session for which to retrieve mood data
    responses:
      200:
        description: Class climate data retrieved successfully
    """
    try:
        class_session_id = request.args.get("class_session_id")

        # Ensure that class_session_id is provided
        if not class_session_id:
            return jsonify({"error": "class_session_id parameter is required"}), 400

        # Retrieve mood data (e.g., for the past 30 days) for the specified class session ID
        recent_moods = Mood.query.filter(Mood.class_session_id == class_session_id, Mood.timestamp > (db.func.now() - timedelta(days=30))).all()
        
        # Calculate mood counts
        mood_counts = {}
        for mood in recent_moods:
            mood_name = mood.mood.lower()
            mood_date = mood.timestamp.strftime("%Y-%m-%d")
            mood_counts[mood_name] = mood_counts.get(mood_name, 0) + 1

        # Format mood data with counts
        mood_data = [{"mood": mood_name, "date": mood_date, "count": count} for mood_name, count in mood_counts.items()]


        return jsonify({"data": mood_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

  
from datetime import datetime, timedelta
from flask import jsonify

@insights_blueprint.route("/insights/class-climate-date", methods=["GET"])
def class_climate_date():
    """
    Class Climate
    ---
    tags:
      - Insights
    parameters:
      - name: class_session_id
        in: query
        type: string
        required: true
        description: The ID of the class session for which to retrieve mood data
    responses:
      200:
        description: Class climate data retrieved successfully
    """
    try:
        class_session_id = request.args.get("class_session_id")

        # Ensure that class_session_id is provided
        if not class_session_id:
            return jsonify({"error": "class_session_id parameter is required"}), 400

        # Calculate the start date for the past 7 days
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)

        # Initialize mood data dictionary
        mood_data = {}

        # Loop over each day within the past 7 days
        current_date = start_date
        while current_date <= end_date:
            next_date = current_date + timedelta(days=1)
            # Retrieve mood data for the specified class session ID and current date
            recent_moods = Mood.query.filter(
                
                Mood.class_session_id == class_session_id,
                Mood.timestamp >= current_date,
                Mood.timestamp < next_date
            ).all()

            # Format mood data with counts for the current date
            mood_counts = {}
            for mood in recent_moods:
                mood_name = mood.mood.lower()
                mood_counts[mood_name] = mood_counts.get(mood_name, 0) + 1

            # Add mood data for the current date to the mood_data dictionary
            mood_data[current_date.strftime("%Y-%m-%d")] = mood_counts

            # Move to the next day
            current_date += timedelta(days=1)

        return jsonify({"data": mood_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@insights_blueprint.route("/insights/export/<int:session_id>", methods=["GET"])
def export_insights_by_Id(session_id):
    """
    Export Insights
    ---
    tags:
      - Insights
    parameters:
      - name: session_id
        in: path
        type: integer
        required: true
        description: ID of the class session
    responses:
      200:
        description: Insights exported successfully
    """
    try:
        # Retrieve mood data for the specified class session (e.g., for the past 30 days)
        recent_moods = Mood.query.filter(Mood.timestamp > (db.func.now() - timedelta(days=30))) \
                                  .filter_by(class_session_id=session_id) \
                                  .all()
        
        # Aggregating mood counts
        mood_counts = {}
        for mood in recent_moods:
            mood_counts[mood.mood] = mood_counts.get(mood.mood, 0) + 1

        # Define CSV file name based on the class session name
        class_session = ClassSession.query.get(session_id)
        if not class_session:
            return jsonify({"error": "Class session not found"}), 404

        filename = f"{class_session.session_name.replace(' ', '_')}_insights_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"

        # Create CSV file
        csv_output = StringIO()
        csv_output.write("mood,count\n")
        for mood, count in mood_counts.items():
            csv_output.write(f"{mood},{count}\n")
        csv_output.seek(0)

        return Response(csv_output, mimetype="text/csv", headers={"Content-Disposition": f"attachment;filename={filename}"}), 200 # Return CSV file as a response object
    except Exception as e:
        return jsonify({"error": str(e)}), 500




'''
Aggregate Mood API:
    /aggregate: GET endpoint to get aggregate class mood.
'''
@mood_blueprint.route("/mood/aggregate", methods=["GET"])
def aggregate_mood():
    """
    Aggregate Mood
    ---
    tags:
      - Mood
    responses:
      200:
        description: Aggregate mood data retrieved successfully
    """
    try:
        # Retrieve mood data (e.g., for the past 30 days)
        recent_moods = Mood.query.filter(Mood.timestamp > (db.func.now() - timedelta(days=30))).all()
        mood_data = [mood.mood for mood in recent_moods]

        # Calculate mood insights
        mood_counts = {mood: mood_data.count(mood) for mood in set(mood_data)}

        return jsonify({"data": mood_counts}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


'''
Explanations API:

    Route: /api/explanations
    Endpoints:
        /add: POST endpoint for students to add optional explanations for their mood selections.
        /list: GET endpoint to retrieve explanations for mood selections.
'''

@mood_blueprint.route("/mood/explanations/add", methods=["POST"])
def add_explanation():
    """
    Add Explanation
    ---
    tags:
      - Mood
    parameters:
      - name: explanation
        in: formData
        type: string
        required: true
    responses:
      201:
        description: Explanation added successfully
      400:
        description: Invalid explanation input
    """
    try:
        explanation = request.json.get("explanation")

        # Validate explanation input (optional)
        if not explanation or not isinstance(explanation, str):
            raise BadRequest("Invalid explanation input")

        # Store explanation data in the database
        new_explanation = Explanation(explanation=explanation)
        db.session.add(new_explanation)
        db.session.commit()

        return jsonify({"message": "Explanation added successfully"}), 201
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@mood_blueprint.route("/mood/explanations/list", methods=["GET"])
def list_explanations():
    """
    List Explanations
    ---
    tags:
      - Mood
    responses:
      200:
        description: Explanations retrieved successfully
    """
    try:
        # Retrieve all explanation data
        all_explanations = Explanation.query.all()
        explanation_data = [explanation.explanation for explanation in all_explanations]

        return jsonify({"data": explanation_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Mood routes
@mood_blueprint.route("/mood/select", methods=["POST"])
def select_mood():
    try:
        mood = request.json.get("mood")
        session_token = request.headers.get("Authorization")

        # Extract class session ID from the session token
        _, class_session_id = session_token.split("-")

        # Validate mood input
        if not mood or not isinstance(mood, str):
            raise BadRequest("Invalid mood input")

        # Check if the class session exists
        class_session = ClassSession.query.get(class_session_id)
        if not class_session:
            raise BadRequest("Invalid class session")

        # Store mood data in the database, associating it with the class session
        new_mood = Mood(user_id="anonymous", mood=mood, timestamp=datetime.utcnow(), class_session_id=class_session_id)
        db.session.add(new_mood)
        db.session.commit()

        return jsonify({"message": "Mood selection successful"}), 201
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500




@mood_blueprint.route("/mood/track", methods=["GET"])
def track_mood():
    """
    Track Mood
    ---
    tags:
      - Mood
    responses:
      200:
        description: Mood data retrieved successfully
    """
    try:
        
        


        # Retrieve mood data (e.g., for the past 24 hours)
        recent_moods = Mood.query.filter(Mood.timestamp > (db.func.now() - timedelta(days=1))).all()

        mood_data = [{"mood": mood.mood, "timestamp": mood.timestamp.strftime("%Y-%m-%d %H:%M:%S")} for mood in recent_moods]

        return jsonify({"data": mood_data}), 200
    except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        traceback_str = traceback.format_exc()
        error_details = {"error": error_message, "traceback": traceback_str}
        return jsonify(error_details), 500


@mood_blueprint.route("/mood/list", methods=["GET"])
def list_mood():
    """
    List Mood
    ---
    tags:
      - Mood
    responses:
      200:
        description: Mood data retrieved successfully
    """
    try:
        # Retrieve all mood data
        all_moods = Mood.query.all()
        mood_data = []

        for mood in all_moods:
            timestamp = mood.timestamp.strftime("%Y-%m-%d %H:%M:%S") if mood.timestamp else None
            mood_data.append({"mood": mood.mood, "timestamp": timestamp})

        return jsonify({"data": mood_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



'''Time-Based Tracking API:

    Route: /api/tracking
    Endpoints:
        /add: POST endpoint to capture mood data at specific points during the lesson or at regular intervals throughout the day.
        /history: GET endpoint to retrieve mood tracking history.'''

@mood_blueprint.route("/mood/tracking/add", methods=["POST"])
def add_tracking():
    """
    Add Tracking
    ---
    tags:
      - Mood
    parameters:
      - name: mood
        in: formData
        type: string
        required: true
    responses:
      201:
        description: Tracking data added successfully
      400:
        description: Invalid tracking input
    """
    try:
        mood = request.json.get("mood")

        # Validate tracking input (optional)
        if not mood or not isinstance(mood, str):
            raise BadRequest("Invalid tracking input")

        # Store tracking data in the database
        new_tracking = Tracking(mood=mood)
        db.session.add(new_tracking)
        db.session.commit()

        return jsonify({"message": "Tracking data added successfully"}), 201
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@mood_blueprint.route("/mood/tracking/history", methods=["GET"])
def tracking_history():
    """
    Tracking History
    ---
    tags:
      - Mood
    responses:
      200:
        description: Tracking history retrieved successfully
    """
    try:
        # Retrieve all tracking data
        all_tracking = Tracking.query.all()
        tracking_data = [{"mood": tracking.mood, "timestamp": tracking.timestamp.strftime("%Y-%m-%d %H:%M:%S")} for tracking in all_tracking]

        return jsonify({"data": tracking_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


'''
Engagement Features API:

    Route: /api/engagement
    Endpoints:
        /activities: GET endpoint to suggest activities or discussion topics based on the overall mood.
        /positive-reinforcement: GET endpoint to highlight positive moods with encouraging messages or animations.
        /motivational-quotes: GET endpoint to display uplifting quotes based on the chosen mood.
        /anonymous-polls: POST endpoint to ask quick, mood-related questions to gauge engagement.
'''

@mood_blueprint.route("/mood/engagement/activities", methods=["GET"])
def engagement_activities():
    """
    Engagement Activities
    ---
    tags:
      - Mood
    responses:
      200:
        description: Engagement activities retrieved successfully
    """
    try:
        # Retrieve mood data (e.g., for the past 7 days)
        current_timestamp = db.func.now()
        current_app.logger.info("Current Timestamp: %s", current_timestamp)

        # Retrieve mood data (e.g., for the past 7 days)
        seven_days_ago = current_timestamp - timedelta(days=7)
        print("Seven Days Ago:", seven_days_ago)

        recent_moods = Mood.query.filter(Mood.timestamp > seven_days_ago).all()
        mood_data = [mood.mood for mood in recent_moods]

        # Print or log the mood data
        print("Mood Data:", mood_data)
        # Calculate mood insights
        mood_counts = {mood: mood_data.count(mood) for mood in set(mood_data)}

        # Suggest activities or discussion topics based on the overall mood
        engagement_activities = {
            "positive": "Share a positive experience with a classmate",
            "neutral": "Discuss a topic of interest with a classmate",
            "negative": "Share a concern with a classmate"
        }

        return jsonify({"data": engagement_activities}), 200
    except Exception as e:
        current_app.logger.error("Error: %s", str(e))
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500



# Mood routes
@mood_blueprint.route("/mood/engagement/positive-reinforcement", methods=["GET"])
def positive_reinforcement():
    """
    Positive Reinforcement
    ---
    tags:
      - Mood
    responses:
      200:
        description: Positive reinforcement retrieved successfully
    """
    try:
        # Retrieve mood data (e.g., for the past 7 days)
        recent_moods = Mood.query.filter(Mood.timestamp > (db.func.now() - db.timedelta(days=7))).all()
        mood_data = [mood.mood for mood in recent_moods]

        # Calculate mood insights
        mood_counts = {mood: mood_data.count(mood) for mood in set(mood_data)}

        # Highlight positive moods with encouraging messages or animations
        positive_reinforcement = {
            "positive": "Great job! Keep up the positive energy!",
            "neutral": "You're doing great! Keep it up!",
            "negative": "You're not alone. We're here to support you!"
        }

        return jsonify({"data": positive_reinforcement}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@mood_blueprint.route("/mood/engagement/motivational-quotes", methods=["GET"])
def motivational_quotes():
    """
    Motivational Quotes
    ---
    tags:
      - Mood
    responses:
      200:
        description: Motivational quotes retrieved successfully
    """
    try:
        # Retrieve mood data (e.g., for the past 7 days)
        recent_moods = Mood.query.filter(Mood.timestamp > (db.func.now() - db.timedelta(days=7))).all()
        mood_data = [mood.mood for mood in recent_moods]

        # Calculate mood insights
        mood_counts = {mood: mood_data.count(mood) for mood in set(mood_data)}

        # Display uplifting quotes based on the chosen mood
        motivational_quotes = {
            "positive": "You are capable of amazing things!",
            "neutral": "You are stronger than you think!",
            "negative": "Tough times never last, but tough people do!"
        }

        return jsonify({"data": motivational_quotes}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@mood_blueprint.route("/mood/engagement/anonymous-polls", methods=["POST"])
def anonymous_polls():
    """
    Anonymous Polls
    ---
    tags:
      - Mood
    parameters:
      - name: question
        in: formData
        type: string
        required: true
      - name: options
        in: formData
        type: string
        required: true
    responses:
      201:
        description: Anonymous poll created successfully
      400:
        description: Invalid poll input
    """
    try:
        question = request.json.get("question")
        options = request.json.get("options")

        # Validate poll input (optional)
        if not question or not options or not isinstance(question, str) or not isinstance(options, list):
            raise BadRequest("Invalid poll input")

        # Store poll data in the database
        new_poll = Poll(question=question, options=options)
        db.session.add(new_poll)
        db.session.commit()

        return jsonify({"message": "Anonymous poll created successfully"}), 201
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@mood_blueprint.route("/mood/engagement/anonymous-polls", methods=["GET"])
def list_polls():
    """
    List Polls
    ---
    tags:
      - Mood
    responses:
      200:
        description: Polls retrieved successfully
    """
    try:
        # Retrieve all poll data
        all_polls = Poll.query.all()
        poll_data = [{"question": poll.question, "options": poll.options} for poll in all_polls]

        return jsonify({"data": poll_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Insights routes
@insights_blueprint.route("/insights/mood", methods=["GET"])
def mood_insights():
    """
    Mood Insights
    ---
    tags:
      - Insights
    responses:
      200:
        description: Mood insights retrieved successfully
    """
    try:
        # Retrieve mood data (e.g., for the past 7 days)
        recent_moods = Mood.query.filter(Mood.timestamp > (db.func.now() - timedelta(days=7))).all()
        mood_data = [mood.mood for mood in recent_moods]

        # Calculate mood insights
        mood_counts = {mood: mood_data.count(mood) for mood in set(mood_data)}

        return jsonify({"data": mood_counts}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

#Export insights as a CSV for 30 days
@insights_blueprint.route("/insights/export", methods=["GET"])
def export_insights():
    """
    Export Insights
    ---
    tags:
      - Insights
    responses:
      200:
        description: Insights exported successfully
    """
    try:
        # Retrieve mood data (e.g., for the past 30 days)
        recent_moods = Mood.query.filter(Mood.timestamp > (db.func.now() - timedelta(days=30))).all()
        mood_data = [{"mood": mood.mood, "timestamp": mood.timestamp.strftime("%Y-%m-%d %H:%M:%S")} for mood in recent_moods]

        # Create CSV file
        csv_output = StringIO()
        csv_output.write("mood,timestamp\n")
        for mood in mood_data:
            csv_output.write(f"{mood['mood']},{mood['timestamp']}\n")
        csv_output.seek(0)

        return Response(csv_output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=mood_data.csv"}), 200 # Return CSV file as a response object
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# Security APIs
@auth_blueprint.route("/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh_token():
    """
    Refresh Token
    ---
    tags:
      - Authentication
    responses:
      200:
        description: Token refreshed successfully
      401:
        description: Unauthorized
    """
    jti = get_jwt_identity()
    access_token = create_access_token(identity=jti, expires_delta=timedelta(days=1))

    return jsonify({"access_token": access_token}), 200


@auth_blueprint.route("/security/anonymity-policy", methods=["GET"])
def anonymity_policy():
    """
    Anonymity Policy
    ---
    tags:
      - Security
    responses:
      200:
        description: Anonymity policy retrieved successfully
    """
    return jsonify({"policy": "We maintain complete anonymity for students' mood selections and explanations"}), 200    


@auth_blueprint.route("/security/data-security-policy", methods=["GET"])
def data_security_policy():

    """
    Data Security Policy
    ---
    tags:
      - Security
    responses:
      200:
        description: Data security policy retrieved successfully
    """
    return jsonify({"policy": "We ensure secure data storage and access protocols to protect student privacy"}), 200    


@auth_blueprint.route("/security/data-usage-policy", methods=["GET"])
def data_usage_policy():
    """
    Data Usage Policy
    ---
    tags:
      - Security
    responses:
      200:
        description: Data usage policy retrieved successfully
    """
    return jsonify({"policy": "We inform students about how their data is collected, used, and protected"}), 200



  # Assuming you have models for Explanation, Reason, and Mood


@mood_blueprint.route("/mood/submit", methods=["POST"])
def submit_mood_form():
    try:
        # Extract session token from the Authorization header
        session_token = request.headers.get("Authorization")
        if not session_token:
            return jsonify({"error": "Authorization header is missing"}), 400

        # Extract class session ID from the session token
        _, class_session_id = session_token.split("-")

        # Verify the class session ID here (you need to implement this logic)
        class_session = ClassSession.query.get(class_session_id)
        if not class_session:
            return jsonify({"error": "Invalid class session"}), 400

        # Extract data from the request
        data = request.json

        # Handle mood selection
        selected_mood = data.get("selectedMood")
        if not selected_mood or not isinstance(selected_mood, str):
            return jsonify({"error": "Invalid mood input"}), 400

        # Handle reason selection
        selected_reasons = data.get("selectedReasons")
        if not selected_reasons or not isinstance(selected_reasons, list):
            return jsonify({"error": "Invalid reasons input"}), 400

        # Handle explanation
        explanation_text = data.get("explanation")
        if explanation_text and not isinstance(explanation_text, str):
            return jsonify({"error": "Invalid explanation input"}), 400

        # Store new mood in the database

        mood = Mood(mood=selected_mood)
        db.session.add(mood)
        
        # Store new reasons in the database and associate them with the mood
        for reason_label in selected_reasons:
            
            reason = Reason(label=reason_label)
            db.session.add(reason)
            mood.reasons.append(reason)
            

        # Add explanation if provided and associate it with the mood
        if explanation_text:
            explanation = Explanation(explanation=explanation_text)
            db.session.add(explanation)
            mood.explanations.append(explanation)

        # Associate the mood with the class session
        class_session.moods.append(mood)

        # Commit changes to the database
        db.session.commit()

        return jsonify({"message": "Form submitted successfully"}), 200
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500





# Error handling
@auth_blueprint.errorhandler(BadRequest)
@mood_blueprint.errorhandler(BadRequest)
@insights_blueprint.errorhandler(BadRequest)
def handle_bad_request(e):
    response = jsonify({"error": "Bad request"})
    response.status_code = 400
    return response

@auth_blueprint.errorhandler(NotFound)
@mood_blueprint.errorhandler(NotFound)
@insights_blueprint.errorhandler(NotFound)
def handle_not_found(e):
    response = jsonify({"error": "Resource not found"})
    response.status_code = 404
    return response

@auth_blueprint.errorhandler(Unauthorized)
@mood_blueprint.errorhandler(Unauthorized)
@insights_blueprint.errorhandler(Unauthorized)
def handle_unauthorized(e):
    response = jsonify({"error": "Unauthorized"})
    response.status_code = 401
    return response

@auth_blueprint.errorhandler(InternalServerError)
@mood_blueprint.errorhandler(InternalServerError)
@insights_blueprint.errorhandler(InternalServerError)
def handle_internal_server_error(e):
    response = jsonify({"error": "Internal server error"})
    response.status_code = 500
    return response

@auth_blueprint.errorhandler(Exception)
@mood_blueprint.errorhandler(Exception)
@insights_blueprint.errorhandler(Exception)
def handle_exception(e):
    response = jsonify({"error": "An unexpected error occurred"})
    response.status_code = 500
    return response