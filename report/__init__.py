from flask import Flask
from flask_login import LoginManager
from datetime import timedelta
from flask_mail import Mail
import yaml
from flask_jwt_simple import JWTManager

#  creates a Flask application object
app = Flask(__name__)

#  load config from the config.yml file
conf = yaml.safe_load(open('report/config.yml'))
email_noreply = conf['email']['noreply']
email_noreply_pwd = conf['email']['noreply_password']
email_helpdesk=conf['email']['helpdesk']
email_logerrors=conf['email']['logerrors']

redirect_uri = conf['ford']['redirect_uri']
TOKEN_URL=conf['ford']['TOKEN_URL']
BASE_URL=conf['ford']['BASE_URL']
payload=conf['ford']['payload']

#  load config from the config.py file
app.config.from_object('report.config.BaseConfig')

# set a Secret key to add the security to the client side session
app.config['SECRET_KEY']='78e70cb1cfc894c1ab62fc9cf2b16dda'
# set session time to 60 minutes
app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=60)

# set mail server for outlook
app.config['MAIL_SERVER'] = 'smtp.office365.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = email_noreply
app.config['MAIL_PASSWORD'] = email_noreply_pwd

# set config to use for the application 
app.config['MAIL_HELPDESK'] = email_helpdesk
app.config['MAIL_LOGERRORS'] = email_logerrors

app.config['redirect_uri'] = redirect_uri
app.config['TOKEN_URL'] = TOKEN_URL
app.config['BASE_URL'] = BASE_URL
app.config['payload'] = payload

# register JWTManage extension with the flask app.
# This object is used to hold the JWT settings and callback functions
jwt_m = JWTManager(app)

# all emails are sent using the configuration values of the application
mail = Mail(app)

# import views-connect the application instance to the view functions, otherwise, Flask will not be aware of your view functions.
from report import routes
