from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,BooleanField,TextAreaField,TextField,SelectField
from wtforms.validators import DataRequired,Length,Email,EqualTo,ValidationError
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import create_session
from sqlalchemy import create_engine,Column,String,text
import yaml,urllib,re
from flask import flash,session

#  load config from the config.yml file
conf = yaml.safe_load(open('report/config.yml'))

# automapping the exsiting User table
Base = automap_base()
class User(Base):
    __tablename__ = 'Users'

    id = Column('UserID',String,primary_key=True)
    username = Column('UserName', String)
    email = Column('UserEmail',String)
    password = Column('UserPassword', String)

# set the database link
conn = urllib.parse.quote_plus(
        "DRIVER={ODBC Driver 17 for SQL Server};SERVER=" + conf['sql']['server'] + ";DATABASE=" + conf['sql']['database'] + ";UID=" + conf['sql']['username'] + ";PWD=" + conf['sql']['password'])
engine = create_engine("mssql+pyodbc:///?odbc_connect=%s" % conn, connect_args={"encoding": "utf8"},pool_recycle=3600)

# reflect the schema of an existing table and produce mappings
Base.prepare(engine, reflect=True)
sqlsession = create_session(bind = engine)

# create login form 
class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
  
    submit = SubmitField('Login')

# create verification form for two factor authentication
class VerifyForm(FlaskForm):
    otp = StringField('OTP',validators=[DataRequired()])
    submit = SubmitField('Verify')

# create choice form to choose car or cv report
class ListForm_ALL(FlaskForm):
    list = SelectField('Report List',validators=[DataRequired()],choices=[
        ('gbr_car', 'GBR Car'),
        ('gbr_cv', 'GBR CV'),
        ('irl_car', 'Ireland Car'),
        ('irl_cv', 'Ireland CV')])
    submit = SubmitField('Confirm')

class ListForm_GBR(FlaskForm):
    list = SelectField('Report List',validators=[DataRequired()],choices=[
        ('gbr_car', 'GBR Car'),
        ('gbr_cv', 'GBR CV')])
    submit = SubmitField('Confirm')

class ListForm_IRL(FlaskForm):
    list = SelectField('Report List',validators=[DataRequired()],choices=[
        ('irl_car', 'Ireland Car'),
        ('irl_cv', 'Ireland CV')])
    submit = SubmitField('Confirm')

# create contact form          
class ContactForm(FlaskForm):
    name = TextField("Name", validators=[DataRequired("Please enter your name.")])
    email = TextField("Email", validators=[DataRequired("Please enter your email address."), Email()])
    subject = TextField("Subject", validators=[DataRequired("Please enter a subject.")])
    message = TextAreaField("Message", validators=[DataRequired("Please enter a message.")])
    submit = SubmitField("Send")

# create form to hold tab closure time stamp
class LogForm(FlaskForm):
    name = StringField('Data')