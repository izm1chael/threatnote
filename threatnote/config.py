from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
import os

# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
#    with app.app_context():

    basedir = os.path.abspath(os.path.dirname(__file__))
    load_dotenv(os.path.join(basedir, '.env'))
    app.config['SERVER_NAME'] = os.environ.get('SERVER_NAME') or 'local.docker:5000'

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'no_secret_key_set'
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI') or \
        'sqlite:///' + os.path.join(basedir, 'db/threatnote.db')

    app.config['OTX_API_KEY'] = os.environ.get('OTX_API_KEY') 

    app.config['SHODAN_API_KEY'] = os.environ.get('SHODAN_API_KEY')


    app.config['RISKIQ_USERNAME'] = os.environ.get('RISKIQ_USERNAME')
    app.config['RISKIQ_KEY'] = os.environ.get('RISKIQ_KEY')
    app.config['GREYNOISE_API_KEY'] = os.environ.get('GREYNOISE_API_KEY')
    app.config['EMAILREP_API_KEY'] = os.environ.get('EMAILREP_API_KEY')
    app.config['VT_API_KEY'] = os.environ.get('VT_API_KEY')
    app.config['MISP_API_KEY'] = os.environ.get('MISP_API_KEY')
    app.config['MISP_URL'] = os.environ.get('MISP_URL')
    app.config['HIBP_API_KEY'] = os.environ.get('HIBP_API_KEY')

 
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from models import User

    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))

    # blueprint for auth routes in our app
    from auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
