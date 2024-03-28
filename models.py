from database import db
from datetime import datetime


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    password = db.Column(db.String)
    email = db.Column(db.String)
    is_anonymous = db.Column(db.Boolean, default=False)
    name = db.Column(db.String)
    age = db.Column(db.Integer)
    is_active = db.Column(db.Boolean)
    role = db.Column(db.String)
    enrolled_sessions = db.relationship('ClassSession', secondary='class_session_students', back_populates='students')

    def serialize(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "name": self.name,
            "age": self.age,
            "is_active": self.is_active,
            "role": self.role
        }





class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String)
    feedback = db.Column(db.String)
    timestamp = db.Column(db.DateTime)

    def serialize(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "feedback": self.feedback,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }


class BlacklistToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String)

    def serialize(self):
        return {
            "id": self.id,
            "token": self.token
        }

class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String)
    question = db.Column(db.String)
    answer = db.Column(db.String)
    timestamp = db.Column(db.DateTime)

    def serialize(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "question": self.question,
            "answer": self.answer,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }

class Insights(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String)
    insights = db.Column(db.String)
    timestamp = db.Column(db.DateTime)

    def serialize(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "insights": self.insights,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }



class UserMood(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String)
    mood = db.Column(db.String)
    timestamp = db.Column(db.DateTime)

    def serialize(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "mood": self.mood,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }
    
class UserInsights(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String)
    insights = db.Column(db.String)
    timestamp = db.Column(db.DateTime)

    def serialize(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "insights": self.insights,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }
    

class Tracking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String)
    mood = db.Column(db.String)
    insights = db.Column(db.String)
    timestamp = db.Column(db.DateTime)

    def serialize(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "mood": self.mood,
            "insights": self.insights,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }
    

  

class ClassSessionStudents(db.Model):

    class_session_id = db.Column(db.Integer, db.ForeignKey('class_session.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)


class ClassSession(db.Model):
    __tablename__ = 'class_session'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_name = db.Column(db.String, unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    moods = db.relationship('Mood', backref='session_moods', lazy=True)
    students = db.relationship('User', secondary='class_session_students', back_populates='enrolled_sessions')
    
    def serialize(self):
        return {
            "id": self.id,
            "code": self.code,
            "teacher_id": self.teacher_id,
            "session_name": self.session_name,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }

class Mood(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String)
    mood = db.Column(db.String)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    class_session_id = db.Column(db.Integer, db.ForeignKey('class_session.id'))

    class_session = db.relationship('ClassSession', back_populates='moods')

    explanations = db.relationship('Explanation', back_populates='mood')
    reasons = db.relationship('Reason', back_populates='mood')


    def serialize(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "mood": self.mood,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "class_session_id": self.class_session_id
        }

class Explanation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String)
    explanation = db.Column(db.String)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    mood_id = db.Column(db.Integer, db.ForeignKey('mood.id'))
    mood = db.relationship('Mood', back_populates='explanations')

    def serialize(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "explanation": self.explanation,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "class_session_id": self.class_session_id
        }

class Reason(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    mood_id = db.Column(db.Integer, db.ForeignKey('mood.id'))
    mood = db.relationship('Mood', back_populates='reasons')

    def serialize(self):
        return {
            "id": self.id,
            "label": self.label,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "class_session_id": self.class_session_id
        }
