import os
import binascii
from flask import  render_template, request, redirect, flash, url_for, jsonify, abort, Response
from flask_login import login_required, current_user
from models import User, Organization
from lib import add_db_entry, get_comments
from main import app
from config import db
from lib import add_db_entry, get_user_info
from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/user_webhooks', methods=['GET', 'POST'])
@login_required
def webhooks():
    if current_user.role=='admin':
        user=User.query.filter_by(id=current_user.id).first()
        org=Organization.query.filter_by(id=user.organization).first()
        if request.method =='POST':
            org.slack_webhook = request.form.get('slack_webhook')
            org.slack_webhook_on_report_create = request.form.get('slack_webhook_on_report_create') != None
            org.slack_webhook_on_req_create = request.form.get('slack_webhook_on_req_create') != None
            org.slack_webhook_on_req_update = request.form.get('slack_webhook_on_req_update') != None
    
            db.session.commit()
            db.session.flush()
            flash('Webhook Saved.')
        return render_template('user_webhooks.html',page_title='Webhooks', org=org)
    else:
        abort(401)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def user_settings():
    if request.method =='POST':
        email = request.form.get('email')
        name = request.form.get('name')
        
        user=User.query.filter_by(id=current_user.id).first()
        
        ok=True
        if not email:
            flash('Changes not saved. Email can not be blank.')
            ok=False
             
        elif email.lower() != user.email.lower():
            #gotta check to be sure there isn't another record for that email
            check_user= User.query.filter_by(email=email).filter_by(id != current_user.id).first()
            if check_user:
                flash('Changes not saved. Another user record exists for the email address {}.'.format(email))
                ok=False
        if not name:
                flash('Changes not saved. Name can not be blank.')
                ok=False
        if ok:
            user.name=name
            user.email=email
            db.session.commit()
            db.session.flush()
            
    return render_template('user_settings.html',page_title='Settings')

@app.route('/regenerate_api')
@login_required
def regenerate_api_key():
    goto=request.args.get('goto')
    user_id=request.args.get('user_id')
    if not user_id:
        user_id=current_user.id
    api_key = binascii.b2a_hex(os.urandom(16)).decode()
    #I know nearly impossible but not impossible that the same api_key is generated twice
    api_key = '{}{}'.format(user_id,api_key)
    User.query.filter_by(id=user_id).update({'tn_api_key':api_key})
    db.session.commit()
    db.session.flush()
    if goto:
        flash('Api key regenerated')
        return redirect(url_for(goto))
    else:
        return render_template('user_settings.html')

@app.route('/integrations')
@login_required
def integrations():
    if current_user.role=='admin':
        user_details = get_user_info(current_user.id)
        return render_template('integrations.html',user_details=user_details,page_title="Integrations")
    else:
        abort(401)# only admins can access

@app.route('/users')
@login_required
def users_list():
    if current_user.role=='admin':
        users = User.query.filter_by(organization=current_user.organization).order_by(User.name).all()
        return render_template('users.html',users=[u.__dict__ for u in users],page_title="Users")
    else:
        abort(401)# only admins can access

@app.route('/user/new')
@app.route('/user/edit/<user_id>', methods=['GET'])
def user_new(user_id=None):
    if not user_id:
        user_id=request.args.get('user_id')
    if current_user.role=='admin':
        if user_id:
            user=User.query.filter_by(id=user_id).first()
        else:
            user=User()    
        return render_template('edit_user.html',user_info=user,page_title='Users')
    else:
        abort(401)# only admins can access

@app.route('/user/edit/<user_id>')
@login_required
def user_edit(user_id):
    if current_user.role=='admin':
        user=User.query.filter_by(id=user_id).first()
        
        return render_template('edit_user.html',user_info=user,page_title='Edit User')
    else:
        abort(401)# only admins can access

@app.route('/check_email')
@login_required
def check_user_email():
    user_id=request.args.get('user_id', -1)
    ret={'id':'None'}
    
    email=request.args.get('email')
    
    if user_id and email:
        user=User.query.filter_by(email=email).first()
        if user and str(user.id) !=str(user_id):
            ret['id']=user.id
    return jsonify(ret)   
    
    
@app.route('/user/delete/<user_id>')
@login_required
def user_delete(user_id):
    if current_user.role=='admin':
        #admins cant delete themselves
        if user_id ==current_user.id:
            flash('You can not delete yourself.')
        elif user_id==1:
            flash('You can not delete primary admin.')
        elif user_id:
            user=User.query.filter_by(id=user_id).delete()
            flash('User deleted.')
            db.session.commit() 
        
        return redirect(url_for('users_list'))
    else:
        abort(401)# only admins can access

@app.route('/users/save', methods=['POST'])
@app.route('/users/save/<user_id>', methods=['POST'])
@login_required
def user_submit(user_id=None):
    if current_user.role=='admin':
        if user_id:
            user=User.query.filter_by(id=user_id).first()
        else:
            user=User()
            
        ok=True
        name=request.form.get('name')
        email=request.form.get('email')
        role=request.form.get('role')
        password=request.form.get('password')
        confirm_password=request.form.get('confirm_password')

        if name is None:
            flash('Name is blank')
            ok=False
            
        if email is None:
            flash('Email is blank')
            ok=False
        else:
            existing_user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database
            if existing_user and (user is None or  existing_user.id != user.id): # if a user is found, we want to redirect back to signup page so user can try again
                flash('Email address already exists')
                ok=False

        if role is None:
            flash('Select a role')
            ok=False
        elif current_user.id==user_id and role=='user':
            flash('You cannot change your role from admin to user')
            ok=False
        elif user_id==1 and role=='user':
            flash('You cannot the primary admin\'s role from admin to user')
            ok=False
        
        if password is not None:
            if confirm_password !=password:
                flash('Passwords do not match')
                ok=False
        elif user_id is None:
            flash('Enter a password')
            ok=False

        user.name=name
        user.email=email
        user.role=role
        if password:
            user.password=generate_password_hash(password, method='sha256')
        if(ok):
            if user_id:
                db.session.commit()
                db.session.flush()
            else:
                #add
                user.organization=current_user.organization
                user.tn_api_key=binascii.b2a_hex(os.urandom(16)).decode()
                add_db_entry(user)
            flash('User saved')
            return redirect(url_for('users_list'))
        else:
            return render_template('edit_user.html',user_info=user,page_title='Users')
#            return redirect(url_for('user_edit', user_id=user_id))
    else:
        abort(401)# only admins can access



@app.route('/change_password')
@login_required
def change_password():
    return render_template('change_password.html',page_title='Change Password')

@app.route('/change_password', methods=['POST'])
@login_required
def update_password():
    args = request.form
    password=args.get('current_password')
    #password=generate_password_hash(args.get('current_password'), method='sha256')
    if not check_password_hash(current_user.password, password):
            # Need to flash message that password is incorrect
            flash('Current password is incorrect.')
            print('incorrect')
    else:
        if args.get('new_password') == args.get('confirm_password'):
            password = args.get('confirm_password')
            password=generate_password_hash(password, method='sha256')
            User.query.filter_by(id=current_user.id).update({'password':password})
            db.session.commit()
            db.session.flush()
            flash('Password changed.')

        else:
            flash('New passwords do not match.')
    return render_template('change_password.html')



@app.route('/update_integrations',methods=['POST'])
@login_required
def update_integrations():
    current_user_id = current_user.id
    form_data = request.form
    
    user=User.query.filter_by(id=current_user_id).first()
    org_data={}
    org_data['ipinfo_enabled']=True if form_data.get('ipinfo_enabled') else False
    org_data['whois_enabled']=True if form_data.get('whois_enabled') else False

    org_data['vt_enabled']=True if form_data.get('vt_enabled') else False
    org_data['vt_api_key']=form_data.get('vt_api_key')
    
    org_data['emailrep_enabled']=True if form_data.get('emailrep_enabled') else False    
    org_data['emailrep_api_key']=form_data.get('emailrep_api_key')    
    
    org_data['av_enabled']=True if form_data.get('av_enabled') else False    
    org_data['av_api_key']=form_data.get('av_api_key')    

    org_data['gn_enabled']=True if form_data.get('gn_enabled') else False
    org_data['gn_api_key']=form_data.get('gn_api_key')    

    org_data['riskiq_enabled']=True if form_data.get('riskiq_enabled') else False
    org_data['riskiq_api_key']=form_data.get('riskiq_api_key')
    org_data['riskiq_username']=form_data.get('riskiq_username')

    org_data['shodan_enabled']=True if form_data.get('shodan_enabled') else False
    org_data['shodan_api_key']=form_data.get('shodan_api_key')

    org_data['urlscan_enabled']=True if form_data.get('urlscan_enabled') else False

    org_data['misp_enabled']=True if form_data.get('misp_enabled') else False
    org_data['misp_api_key']=form_data.get('misp_api_key')
    org_data['misp_url']=form_data.get('misp_url')

    org_data['hibp_enabled']=True if form_data.get('hibp_enabled') else False
    org_data['hibp_api_key']=form_data.get('hibp_api_key')

    org_data['hunter_enabled']=True if form_data.get('hunter_enabled') else False
    org_data['hunter_api_key']=form_data.get('hunter_api_key')

    if current_user.role=='admin':
        Organization.query.filter_by(id=user.organization).update(org_data)
        
    db.session.commit()
    db.session.flush()

    return redirect('/integrations')

