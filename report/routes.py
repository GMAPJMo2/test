# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
# use @app.route to specify which route you want to write code for
#

import os,yaml,urllib,json,jsonify,requests,jwt,re,time
from unicodedata import name
from report.services.pbiembedservice import PbiEmbedService
from report.utils import Utils
from flask import Flask, session, render_template, url_for, flash, redirect, request, abort, send_from_directory, \
    Response,make_response,send_file
from flask_login import login_user, current_user, logout_user, login_required,UserMixin
from report.forms import ContactForm, ListForm_ALL, ListForm_GBR, ListForm_IRL, LogForm
from report import app,mail,jwt_m
from flask_mail import Message
from secure import SecureHeaders, SecureCookie
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import create_session
from sqlalchemy import create_engine,Column,String
from datetime import datetime
import pyodbc
from flask_jwt_simple import jwt_required

dealer_rls = []

# set Security Headers to enhance the security of the web application by enabling browser security policies
secure_headers = SecureHeaders(csp=True, hsts=False, xfo="DENY")
secure_cookie = SecureCookie()

# load the config file
conf = yaml.safe_load(open('report/config.yml'))

@app.after_request
def set_secure_headers(response):
    secure_headers.flask(response)
    return response

# set secure cookies
@app.route("/secure")
def set_secure_cookie():
    resp = Response("Secure")
    secure_cookie.flask(resp, name="spam", value="eggs")
    return resp

# set a function to access the ford login page and return it as a response
def unset_jwt():
    resp = make_response(redirect(app.config['BASE_URL'], 302))
    return resp

# set login url
@app.route('/login')
def login():
    return unset_jwt()



# write to log
def WriteLog():

    logtrycount=1

    # configure database connection
    #conn = pyodbc.connect(Driver='{ODBC Driver 17 for SQL Server}', Server=conf['sql']['server'], Database=conf['sql']['database'], UID=conf['sql']['username'], PWD=conf['sql']['password'])  # set up connection, Trusted_connection='yes' set to use windows password
    sqlcon_server = conf['sql']['server']
    sqlcon_database = conf['sql']['database']
    sqlcon_username = conf['sql']['username']
    sqlcon_password = conf['sql']['password']
    conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER='+sqlcon_server+';DATABASE='+sqlcon_database+';UID='+sqlcon_username+';PWD='+sqlcon_password)
    cur = conn.cursor()

    # get entry values
    logtimenow = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logsql = ("INSERT INTO DEV_AccessLog_SSO ([Name],[Role_SiteCode],[Role_GrpCar],[Role_GrpCV],[LogTime_Token],[LogTime],[Page],[Action]) VALUES (?,?,?,?,?,?,?,?);")       
    log_useremail = session.get('user_email','')
    log_dealer_code = session.get('dealer_code','')
    log_Role_GrpCar = session.get('Role_GrpCar','')
    log_Role_GrpCV = session.get('lole_GrpCV','')
    log_logtimetoken = session.get('logtimetoken','')
    log_logpage = session.get('logpage','')
    log_logaction = session.get('logaction','')
    logentry = [log_useremail,log_dealer_code,log_Role_GrpCar,log_Role_GrpCV,log_logtimetoken,logtimenow,log_logpage,log_logaction]
    print("~ ~ [ "+log_useremail+"|"+log_logtimetoken+" ] ~ ~ Log Entry: "+ str(logentry))
    # logentry = [session["user_email"],session["dealer_code"],session["Role_GrpCar"],session["Role_GrpCV"],session["logtimetoken"],logtimenow,session["logpage"],session["logaction"] ]
    # print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Log Entry: "+ str(logentry))

    # Write entry into database log table
    while logtrycount < 10:
        try:
            cur.execute(logsql, logentry)
            cur.commit()
            print("~ ~ [ "+log_useremail+"|"+log_logtimetoken+" ] ~ ~ Writing to Log SUCCESSFUL on write attempt count "+str(logtrycount))
            return

        except:
            print("~ ~ [ "+log_useremail+"|"+log_logtimetoken+" ] ~ ~ Writing to Log FAILED on write attempt count "+str(logtrycount))
            logtrycount = logtrycount + 1
            cur.close()
            conn.close()
            time.sleep(2)
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER='+sqlcon_server+';DATABASE='+sqlcon_database+';UID='+sqlcon_username+';PWD='+sqlcon_password)
            cur = conn.cursor()

    # retry limit excceded, send email message
    print("~ ~ [ "+log_useremail+"|"+log_logtimetoken+" ] ~ ~ Writing to Log FAILED on write attempt count "+str(logtrycount)+", email message sent to GMAP")
    recount = Message('Ford Reconnect Count', sender=app.config['MAIL_USERNAME'],
                        recipients=[app.config['MAIL_LOGERRORS'], app.config['MAIL_LOGERRORS']])
    recount.body = f'''
                    Ford Site has been trying to reconnect more than {str(logtrycount)} times:
                    User: {log_useremail}
                    Dealer code: {log_dealer_code}
                    Role Car: {log_Role_GrpCar}
                    Role CV: {log_Role_GrpCV}
                    Log time token: {str(log_logtimetoken)}
                    Log time stamp: {str(logtimenow)}
                    Log page: {log_logpage}
                    Log action: {log_logaction}
                    '''
    mail.send(recount)


# set auth route
@app.route('/auth')
def auth():
    # set session
    session.permanent = True
    
    print("#################################################################################################################################################################################################")
    print("####   N E W   U S E R   ########################################################################################################################################################################")
    print("#################################################################################################################################################################################################")

    # get authorization_code
    code=request.args.get('code')
    #print("********** CODE **********")
    #print(code)

    token_url = app.config['TOKEN_URL']

    headers = {"Cache-Control": "no-cache",
               "Content-Type": "application/x-www-form-urlencoded",
               }
    payload = app.config['payload'] + code
    token_response = requests.post(token_url, data=payload, headers=headers)
    
    # get token respnse in json format
    token_result = json.loads(token_response.text)

    #print("********** TOKEN RESULT **********")
    #print(token_result)

    # get access token
    jwt_encoded = token_result['access_token']
    print("********** JWT (ENCODED) **********")
    print(jwt_encoded)

    jwt_decoded = jwt.decode(jwt_encoded, options={"verify_signature": False}, audience = "urn:dspd:resource:dspd_web:prod")
    print("********** JWT (DECODED) **********")
    print(jwt_decoded)

    # Set all session vaiables to be zero
    session['GBR_car_report_id'] = '0'
    session['GBR_cv_report_id'] = '0'    
    session['IRL_car_report_id'] = '0'
    session['IRL_cv_report_id'] = '0'
    session["user_email"] = ''
    session["dealer_code"] = ''
    session["Role_GrpCar"] = 0
    session["Role_GrpCV"] = 0
    session["logpage"] = ''
    session["logaction"] = ''

    # get user information
    user_email = jwt_decoded["mail"]
    commonname = jwt_decoded["commonname"]
    dealer_code = jwt_decoded["fordSiteCode"]
    
    # *** DEV TEST ***

    if "d-testu3" in str(commonname):
        #commonname = 'Account 3, IRL Car / CV Dealer'
        #dealer_code = 'IRL51041'
        commonname = 'Account 3, Retail Dealer'
        dealer_code = 'GBR43243ZB'
        print("~ ~ DEV TEST "+str(commonname)+"; dealer code spoofed to "+str(dealer_code))

    if "d-testu5" in str(commonname):
        dealer_code = 'GBR41138AA'
        commonname = 'Account 5, GBR Car / CV Dealer'
        print("~ ~ DEV TEST "+str(commonname)+"; dealer code spoofed to "+str(dealer_code))

    if "d-testu6" in str(commonname):
        user_email = 'GMAPTestInternal@ford.com'
        commonname = 'Account 6, Internal User'
        print("~ ~ DEV TEST "+str(commonname)+"; email spoofed to "+str(user_email))

    # *** ***
        

    js = jwt_decoded["APS-DLS-Entitlements"]
    role = json.loads(js)
    logtimetoken = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    session["user_email"] = user_email
    session["commonname"] = commonname
    session["dealer_code"] = dealer_code
    session["logtimetoken"] = logtimetoken

    print("********** JWT CONTENT **********")
    print("#~ User Email: "+str(user_email))
    print("#~ User Name: "+str(commonname))
    print("#~ Dealer Code: "+str(dealer_code))
    print("#~ APS-DLS-Entitlements (may not exist...): "+str(role))
    print("*********************************")

    # 1.
    # Test if user is internal (check if email contains @ford.com, and also that a dash exists in commonname. If so, set dealer_rls equal to user_email. If not, use dealer code and group code.
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Checking User Type (Internal YES/NO)...")
    if "@ford.com" in str(user_email) and "-" not in str(commonname):
        # 1 = pass...
        dealer_rls = user_email
        session["dealer_rls"] = str(dealer_rls)
        session['GBR_car_report_id'] = conf['reports']['GBRCarReport']
        session['GBR_cv_report_id'] = conf['reports']['GBRCVReport']
        session['IRL_car_report_id'] = conf['reports']['IRLCarReport']
        session['IRL_cv_report_id'] = conf['reports']['IRLCVReport']
        print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Internal User = YES, Access Granted")
        print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ ReportID GBR CAR: "+str(session['GBR_car_report_id']))
        print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ ReportID GBR CV: "+str(session['GBR_cv_report_id']))
        print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ ReportID IRL CAR: "+str(session['IRL_car_report_id']))
        print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ ReportID IRL CV: "+str(session['IRL_cv_report_id']))
        print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ RLS value: "+str(dealer_rls))
        print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ RLS value (session): "+str(session["dealer_rls"]))
        return redirect(url_for('ReportChoice_INT')) # change to INT once Ireland is ready for launch. Also remember to activate IRL buttons on report page
    else:
        # 1 = fail...
        print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Internal User = NO")
        print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Checking AP-DLS-Entitlement for RoleAssignments...")
        # 2. Test for RoleAssignments
        try:
        
            role1=role["RoleAssignments"]
            roles = re.findall("\'RoleName\': \'.*?\'",str(role1),re.IGNORECASE)
            # print(str(role))
            # print(str(role1))
            # print(str(roles))

            # 2 = pass...
            print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ AP-DLS-Entitlement: RoleAssignments is present: "+str(roles))

            # Set Roles
            if "DSPD_User" in str(roles) or "Dealer User" in str(roles):
                print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ AP-DLS-Entitlement: RoleAssignments contains DSPD_User or Dealer User, ACCESS GRANTED")
                Role_SiteCode = dealer_code
            
            else:
                print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ AP-DLS-Entitlement: RoleAssignments does not contain DSPD_User or Dealer user, ACCESS DENIED")
                Role_SiteCode = ""
                # Redirect to NO ACCESS
                return redirect(url_for('NoAccess'))
                                
            if "DSPD_GROUP_USER_CAR" in str(roles):
                Role_GrpCar = 1
            else:
                Role_GrpCar = 0
        
            if "DSPD_GROUP_USER_CV" in str(roles):
                Role_GrpCV = 10
            else:
                Role_GrpCV = 0
            
            Role_GrpTotal = Role_GrpCar + Role_GrpCV
            session["Role_GrpCar"] = Role_GrpCar
            session["Role_GrpCV"] = Role_GrpCV
    
            print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Role_SiteCode: "+str(Role_SiteCode))
            print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Role_GrpCar: "+str(Role_GrpCar))
            print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Role_GrpCV: "+str(Role_GrpCV))
            print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Role_GrpTotal: "+str(Role_GrpTotal))

            # Determine Country Market: Check Contents of SiteCode
            if "GBR" in str(dealer_code):
                # SiteCode contains GBR...
                print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Country: Site Code contains GBR")
                Role_SiteCode = dealer_code.replace("GBR","")                         
                dealer_rls = Role_SiteCode + str( Role_GrpTotal )  
                session["dealer_rls"] = str(dealer_rls)
                session['GBR_car_report_id'] = conf['reports']['GBRCarReport']
                session['GBR_cv_report_id'] = conf['reports']['GBRCVReport']
                # Redirect to GBR
                return redirect(url_for('ReportChoice_GBR'))

            elif "IRL" in str(dealer_code):
                # SiteCode contains IRL...
                print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Country: Site Code contains IRL")
                Role_SiteCode = dealer_code.replace("IRL","")
                dealer_rls = Role_SiteCode + str( Role_GrpTotal )  
                session["dealer_rls"] = str(dealer_rls)
                session['IRL_car_report_id'] = conf['reports']['IRLCarReport']
                session['IRL_cv_report_id'] = conf['reports']['IRLCVReport']
                # Redirect to IRL
                return redirect(url_for('ReportChoice_IRL'))
                
            else:              
                print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Country: Site Code does not contain GBR or IRL")
                Role_SiteCode = ""
                dealer_rls = Role_SiteCode
                session["dealer_rls"] = str(dealer_rls)
                session["logaction"] = 'Access Denied'
                WriteLog()
                # redirect to NO ACCESS
                return redirect(url_for('NoAccess'))

        except:
            # 2 = fail...
            print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ AP-DLS-Entitlement: RoleAssignments is not present: ACCESS DENIED")
            session["logaction"] = 'Access Denied'
            WriteLog()
            # redirect to NO ACCESS
            return redirect(url_for('NoAccess'))


# DEALER USERS:

# Report Choice List
@app.route('/ReportChoice_GBR',methods=['GET','POST'])
def ReportChoice_GBR():
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Redirecting to ReportChoice DEALER USER GBR...")
    form = ListForm_GBR()
    choice = form.list.data
    if request.method == 'POST' and form.validate_on_submit():
        if choice == 'gbr_car':
            return redirect(url_for('GBR_CAR'))
        elif choice=='gbr_cv':
            return redirect(url_for('GBR_CV'))
    return render_template('ReportChoice.html',form=form)

@app.route('/ReportChoice_IRL',methods=['GET','POST'])
def ReportChoice_IRL():
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Redirecting to ReportChoice DEALER USER IRL...")
    form = ListForm_IRL()
    choice = form.list.data
    if request.method == 'POST' and form.validate_on_submit():
        if choice == 'irl_car':
            return redirect(url_for('IRL_CAR'))
        elif choice=='irl_cv':
            return redirect(url_for('IRL_CAR'))
    return render_template('ReportChoice.html',form=form)

# Report Routes
@app.route('/GBR_CAR')
def GBR_CAR():
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ ReportChoice: GBR Car selected...")
    session['report_id'] = session['GBR_car_report_id']
    session["logpage"] = 'GBR_CAR'
    return redirect(url_for('ReportPBI_GBR'))

@app.route('/IRL_CAR')
def IRL_CAR():
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ ReportChoice: IRL Car selected...")
    session['report_id'] = session['IRL_car_report_id']
    session["logpage"] = 'IRL_CAR'
    return redirect(url_for('ReportPBI_IRL'))

@app.route('/GBR_CV')
def GBR_CV():
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ ReportChoice: GBR CV selected...")
    session['report_id'] = session['GBR_cv_report_id']
    session["logpage"] = 'GBR_CV'
    return redirect(url_for('ReportPBI_GBR'))

@app.route('/IRL_CV')
def IRL_CV():
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ ReportChoice: IRL CV selected...")
    session['report_id'] = session['IRL_cv_report_id']
    session["logpage"] = 'IRL_CV'
    return redirect(url_for('ReportPBI_IRL'))



# INTERNAL Users:

# Report Choice List
@app.route('/ReportChoice_INT',methods=['GET','POST'])
def ReportChoice_INT():
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Redirecting to ReportChoice INTERNAL USER...")
    form = ListForm_ALL()
    choice = form.list.data
    if request.method == 'POST' and form.validate_on_submit():
        if choice == 'gbr_car':
            return redirect(url_for('GBR_CAR_INT'))
        elif choice=='gbr_cv':
            return redirect(url_for('GBR_CV_INT'))
        elif choice=='irl_car':
            return redirect(url_for('IRL_CAR_INT'))
        elif choice=='irl_cv':
            return redirect(url_for('IRL_CV_INT'))
    return render_template('ReportChoice.html',form=form)

# Report routes
@app.route('/GBR_CAR_INT')
def GBR_CAR_INT():
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ ReportChoice: GBR Car selected...")
    session['report_id'] = session['GBR_car_report_id']
    session["logpage"] = 'GBR_CAR'
    return redirect(url_for('ReportPBI_INT'))

@app.route('/IRL_CAR_INT')
def IRL_CAR_INT():
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ ReportChoice: IRL Car selected...")
    session['report_id'] = session['IRL_car_report_id']
    session["logpage"] = 'IRL_CAR'
    return redirect(url_for('ReportPBI_INT'))

@app.route('/GBR_CV_INT')
def GBR_CV_INT():
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ ReportChoice: GBR CV selected...")
    session['report_id'] = session['GBR_cv_report_id']
    session["logpage"] = 'GBR_CV'
    return redirect(url_for('ReportPBI_INT'))

@app.route('/IRL_CV_INT')
def IRL_CV_INT():
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ ReportChoice: IRL CV selected...")
    session['report_id'] = session['IRL_cv_report_id']
    session["logpage"] = 'IRL_CV'
    return redirect(url_for('ReportPBI_INT'))



# ReportPBI:
@app.route('/ReportPBI_GBR')
def ReportPBI_GBR():
    session["logaction"] = 'Report Loaded'
    WriteLog()
    return render_template('ReportPBI_GBR.html')

@app.route('/ReportPBI_IRL')
def ReportPBI_IRL():
    session["logaction"] = 'Report Loaded'
    WriteLog()
    return render_template('ReportPBI_IRL.html')

@app.route('/ReportPBI_INT')
def ReportPBI_INT():
    session["logaction"] = 'Report Loaded'
    WriteLog()
    return render_template('ReportPBI_INT.html')

# PBI Embedded
@app.route('/getembedinfo', methods=['GET'])
def get_embed_info():
    '''Returns report embed configuration'''

    config_result = Utils.check_config(app)
    if config_result is not None:
        return json.dumps({'errorMsg': config_result}), 500
    
    user = session["dealer_rls"]
    role_data = ['User']
    report_id = session['report_id']
    
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ CONNECTING TO PBI, EMBED VALUES:")    
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ User (from dealer_rls): "+str(user))
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Role (hardcoded): "+str(role_data))
    print("~ ~ [ "+session["user_email"]+"|"+session["logtimetoken"]+" ] ~ ~ Report ID: "+str(report_id))

    embed_info = PbiEmbedService().get_embed_params_for_single_report(app.config['WORKSPACE_ID'], report_id, user, role_data)
    session["embed_info"] = embed_info
    return embed_info




# Activity logging
@app.route('/LogPageChange', methods=['POST','GET'])
def LogPageChange():
    form = LogForm()
    if request.method == 'POST':
        infos = str(request.form.listvalues) # get the value from the form
        logaction = str(infos).split("'")[1]
        session["logaction"] = logaction
    WriteLog()
    return 'ok'

# Logout
@app.route("/logout")
def logout():
    session["logaction"] = 'Logout'
    WriteLog() 
    return redirect(url_for('login'))


    
@app.route("/")
@app.route("/home")
def home():
    # This is the starting page
    return redirect(url_for('login'))
    # return redirect(app.config['URL_Sitemk1'])

@app.errorhandler(404)
def error_404(error):
    return render_template('404.html')

@app.errorhandler(403)
def error_403(error):
    return render_template('403.html')

@app.errorhandler(500)
def error_500(error):
    return render_template('500.html')

@app.route("/LoginInstructions")
def LoginInstructions():
    session["logaction"] = 'LoginInstructions'
    WriteLog()
    return render_template('LoginInstructions.html')

@app.route("/TutorialVideos_GBR")
def TutorialVideos_GBR():
    session["logaction"] = 'TutorialVideos'
    WriteLog()
    return render_template('TutorialVideos_GBR.html')

@app.route("/TutorialVideos_IRL")
def TutorialVideos_IRL():
    session["logaction"] = 'TutorialVideos'
    WriteLog()
    return render_template('TutorialVideos_IRL.html')

@app.route("/NoAccess")
def NoAccess():
    return render_template('NoAccess.html')

@app.route("/UserGuide")
def UserGuide():
    path = (os.path.join(app.root_path, 'static', 'DSPD User Guide - Version 2.pdf'))
    session["logaction"] = 'DownloadedUserGuide'
    WriteLog()
    return send_file(path, as_attachment=True,attachment_filename='DSPD User Guide.pdf')

# suport page
@app.route('/support', methods=["GET","POST"])
def support():
    logaction = 'Support'
    session["logaction"] = logaction
    WriteLog()
    form = ContactForm()
    if request.method == 'POST':
        if form.validate() == False:
            flash('All fields are required.')
            return render_template('support.html', form=form)
        else:
            msg = Message(subject=form.subject.data, sender=app.config['MAIL_USERNAME'], recipients=[app.config['MAIL_HELPDESK']])
            msg.body = """
      From: 
      Name: %s 
      Email: %s
      Message: 
      
      %s
      """ % (form.name.data, form.email.data, form.message.data)

            mail.send(msg)
            return render_template('support.html', success=True)

    elif request.method == 'GET':
        return render_template('support.html', form=form)
    
