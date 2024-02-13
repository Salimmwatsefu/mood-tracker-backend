from database import db


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


class Mood(db.Model):
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

class Explanation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String)
    explanation = db.Column(db.String)
    timestamp = db.Column(db.DateTime)

    def serialize(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "explanation": self.explanation,
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