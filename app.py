from flask import Flask
from flask_migrate import Migrate
from flasgger import Swagger
from flask_jwt_extended import JWTManager
import os
from flask_cors import CORS
from routes import auth_blueprint, mood_blueprint, insights_blueprint
from database import db
from extensions import bcrypt
from dotenv import load_dotenv
from datetime import timedelta


def create_app():
    app = Flask(__name__)
    CORS(app)
    load_dotenv()

    app.config['SWAGGER'] = {
        'title': 'Mood Tracker API',
        'uiversion': 3,
        'template': {
            'force_language': 'en',
            'swagger': 'flasgger/swagger.html',
            'oauth2': 'flasgger/oauth2.html',
            'flasgger': 'flasgger/index.html'
        }
    }

    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
    app.config['JWT_BLACKLIST_ENABLED'] = True
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

    with app.app_context():
        db.init_app(app)
        db.create_all()

    bcrypt.init_app(app)
    jwt = JWTManager(app)
    migrate = Migrate(app, db)
    Swagger(app)

    # Register all blueprints at once
    app.register_blueprint(auth_blueprint, url_prefix="/api/v1/")
    app.register_blueprint(mood_blueprint, url_prefix="/api/v1/")
    app.register_blueprint(insights_blueprint, url_prefix="/api/v1/")   

    return app