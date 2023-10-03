from flask import  render_template, request, redirect, flash, url_for, jsonify, abort, Response
from flask_login import login_required, current_user
from flask_weasyprint import HTML, render_pdf
from models import Indicators, Requirements, Reports, Links, User, Consumers, Organization, ReportTags,RequirementReports, RequirementConsumers,Comments
from lib import add_db_entry, get_comments, send_webhook
from main import app
from config import db
import json
from datetime import datetime

@app.route('/active_reqs')
@app.route('/active_reqs/<consumer_id>')
def active_reqs(consumer_id=None):
    return list_reqs(consumer_id)
'''
this now shows active reqs by default by also archived
'''
@app.route('/reqs')
@login_required
def list_reqs(consumer_id=None):
    consumer = request.args.get('consumer')
    show_archived=request.args.get('show_archived', False)=='True'
    if show_archived:
        if consumer_id:
            consumer=Consumers.query.filter_by(id=consumer_id).first().name
            org_id=User.query.filter_by(id=current_user.id).first().organization
            active_reqs = (db.session.query(Requirements)
                .join(RequirementConsumers, Requirements.id == RequirementConsumers.requirement)
                .join(Consumers, Consumers.id == RequirementConsumers.consumer)
                .filter(RequirementConsumers.consumer == consumer_id)
                .filter(Consumers.organization== org_id)
                .all())
        elif consumer:
            org_id=User.query.filter_by(id=current_user.id).first().organization
            active_reqs = (db.session.query(Requirements)
                           .join(RequirementConsumers, Requirements.id == RequirementConsumers.requirement)
                           .join(Consumers, Consumers.id == RequirementConsumers.consumer)
                           .filter(Consumers.name == consumer)
                           .filter(Consumers.organization== org_id)
                           .all())
        else:
            active_reqs = Requirements.query.all()
    else: 
        if consumer_id:
            consumer=Consumers.query.filter_by(id=consumer_id).first().name
            org_id=User.query.filter_by(id=current_user.id).first().organization
            active_reqs = (db.session.query(Requirements)
                .join(RequirementConsumers, Requirements.id == RequirementConsumers.requirement)
                .join(Consumers, Consumers.id == RequirementConsumers.consumer)
                .filter(Requirements.is_archived.is_(False))
                .filter(RequirementConsumers.consumer == consumer_id)
                .filter(Consumers.organization== org_id)
                .all())
        elif consumer:
            org_id=User.query.filter_by(id=current_user.id).first().organization
            active_reqs = (db.session.query(Requirements)
                           .join(RequirementConsumers, Requirements.id == RequirementConsumers.requirement)
                           .join(Consumers, Consumers.id == RequirementConsumers.consumer)
                           .filter(Requirements.is_archived.is_(False))
                           .filter(Consumers.name == consumer)
                           .filter(Consumers.organization== org_id)
                           .all())
        else:
            active_reqs = Requirements.query.filter(Requirements.is_archived.is_(False)).all()

    reqs_list = [u.__dict__ for u in active_reqs]
    req_consumer_dict={}
    #new consumers
    consumers_for_user=db.session.query(Consumers, RequirementConsumers).join(RequirementConsumers, Consumers.id==RequirementConsumers.consumer).join(User, User.organization==Consumers.organization).all()
    for cons, rc in consumers_for_user:
        consumer_list=req_consumer_dict.get(rc.requirement, [])
        consumer_list.append(cons.name)
        req_consumer_dict[rc.requirement]=consumer_list
    
    for req in reqs_list:
        req.pop('_sa_instance_state')
        if req['id'] in  req_consumer_dict:
            req['final_consumers']=', '.join(req_consumer_dict[req['id']])

    return render_template('activereqs.html',reqs=reqs_list, req_consumer=consumer,page_title="Intel Requirements", show_archived=show_archived)

@app.route('/archive_req/<req_id>',methods=['GET', 'POST'])
@login_required
def archive_req(req_id):
    req = Requirements.query.filter_by(id=req_id).first()
    req.is_archived=True
    db.session.commit()
    db.session.flush()
    flash('Requirement archived.')
    return redirect(url_for(request.args.get('landing', 'edit_req'), req_id=req_id))

@app.route('/unarchive_req/<req_id>',methods=['GET', 'POST'])
@login_required
def unarchive_req(req_id):
    req = Requirements.query.filter_by(id=req_id).first()
    req.is_archived=False
    db.session.commit()
    db.session.flush()
    flash('Requirement archived.')
    return redirect(url_for(request.args.get('landing', 'edit_req'), req_id=req_id))

#@app.route('/archived_reqs')
#@login_required
#def archived_reqs():
    #archived_reqs = Requirements.query.filter_by(is_archived=True)
    #reqs_list = [u.__dict__ for u in archived_reqs]
    
#    req_consumer_dict={}
    #new consumers
##    consumers_for_user=db.session.query(Consumers, RequirementConsumers).join(RequirementConsumers, Consumers.id==RequirementConsumers.consumer).join(User, User.organization==Consumers.organization).all()
 #   for consumer, rc in consumers_for_user:
 #       consumer_list=req_consumer_dict.get(rc.requirement, [])
 #       consumer_list.append(consumer.name)
 #       req_consumer_dict[rc.requirement]=consumer_list
 #   reqs_list=Requirements.query.filter(Requirements.is_archived.is_(True)).all()
 #   reqs_list=[r.__dict__ for r in reqs_list]
    
 #   for req in reqs_list:
 #       req.pop('_sa_instance_state')
 #       if req['id'] in  req_consumer_dict:
 #   return render_template('archived_reqs.html',reqs=reqs_list)

@app.route('/delete_req/<req_id>')
@login_required
def delete_req(req_id):
    Requirements.query.filter_by(id=req_id).delete()
    RequirementReports.query.filter_by(requirement=req_id).delete()
    RequirementConsumers.query.filter_by(requirement=req_id).delete()

    db.session.commit() 
    return redirect(url_for('list_reqs'))

@app.route('/edit_req/<req_id>')
@login_required
def edit_req(req_id):
    req_info = Requirements.query.filter_by(id=req_id).first()
#    final_consumers=', '.join([ d['value'] for d  in json.loads(req_info.consumers) if d['value']])
    consumers=db.session.query(Consumers).join(RequirementConsumers, RequirementConsumers.consumer==Consumers.id).filter(RequirementConsumers.requirement==req_id).all()
    final_consumers=', '.join([c.name for c in consumers ])
        
    return render_template('edit_req.html',req_info=req_info, final_consumers=final_consumers,page_title=req_info.title)


@app.route('/new_ir')
@login_required
def new_ir():
    return render_template('ir_wizard.html')

'''
Check to to see if the friendly_id for report already exists
returns id of report if exists else none
Thinking will use some ajax on new reports/edit report so we don't get primary key error
'''
@app.route('/requirements/friendly_id_check/')
@login_required
def req_friendly_id_check(friendly_id=None):
    if friendly_id==None:
        if request.args.get('friendly_id'):
            friendly_id=request.args.get('friendly_id')
        elif request.form.get('friendly_id'):
            friendly_id=request.args.get('friendly_id')
    req=Requirements.query.filter_by(friendly_id=friendly_id).first()
    if req:
        return jsonify({'id':req.id})
    else: 
        return jsonify({'id':'None'})

@app.route('/submit_ir',methods=['POST'])
@login_required
def submit_ir():
    form_data = request.form
#    created_at = datetime.now().strftime('%m-%d-%y %H:%M:%S')
    try:
        time_requirement=datetime.strptime(form_data.get('time_requirement'), '%m/%d/%Y').date()
    except Exception as err:
        time_requirement=None
    if form_data.get('is_edit') == 'True':
        req=Requirements.query.filter_by(id=form_data.get('req_id')).first()
        req.title=form_data.get('title')
        req.summary=form_data.get('summary')
        req.gaps=form_data.get('gaps')
        req.friendly_id=form_data.get('friendly_id')
        req.collection_requirements=form_data.get('collection_requirements')
        req.deliverables=form_data.get('deliverables')
        req.time_requirement=time_requirement
        req.priority=form_data.get('priority')
        #req.is_archived=form_data.get('is_archived', False) #taking this out for now as it automatically archives on switch
        db.session.commit()
        db.session.flush()
        #send a webhook
        hooks=Organization.query.filter(Organization.slack_webhook_on_req_update.is_(True)).all()
        hooks=[hook.slack_webhook for hook in hooks if hook.slack_webhook]
        message='Intel requirement, {}, has been updated. To view the requirement, go to {}{}'.format(req.friendly_id,request.host_url[0:-1], url_for('view_req', req_id=req.id))
        wh_data = {
            "attachments":[
                {
                    "fallback":message,
                    "pretext":message,
                    "color":"#6658EA",
                    "fields":[
                        {
                        "title":"Writer",
                        "value":req.creator,
                        "short":'true'
                        },
                        {
                        "title":"Due Date",
                        "value": req.time_requirement.strftime('%m-%d-%y') if req.time_requirement else "N/A",
                        "short":'true'
                        },
                        {
                        "title":"ID",
                        "value":req.friendly_id,
                        "short":'true'
                        },
                        {
                        "title":"Priority",
                        "value":req.priority,
                        "short":'true'
                        },
                        {
                        "title":"Summary",
                        "value":req.summary,
                        }
                    ]
                }
            ]
            }
        
        send_webhook(wh_data, hooks)

    else:
        req = Requirements(creator=current_user.name,owner=form_data.get('owner'),priority=form_data.get('priority'),title=form_data.get('title'),summary=form_data.get('summary'),gaps=form_data.get('gaps'),friendly_id=form_data.get('friendly_id'),collection_requirements=form_data.get('collection_requirements'),deliverables=form_data.get('deliverables'),time_requirement=time_requirement,is_archived=False )
        add_db_entry(req)
         #send a webhook
        hooks=Organization.query.filter(Organization.slack_webhook_on_req_create.is_(True)).all()
        hooks=[hook.slack_webhook for hook in hooks if hook.slack_webhook]
        message='A new intel requirement, {}, has been created. To view the requirement, go to {}{}'.format(req.friendly_id,request.host_url[0:-1], url_for('view_req', req_id=req.id))
        wh_data = {
            "attachments":[
                {
                    "fallback":message,
                    "pretext":message,
                    "color":"#6658EA",
                    "fields":[
                        {
                        "title":"Writer",
                        "value":req.creator,
                        "short":'true'
                        },
                        {
                        "title":"Due Date",
                        "value":req.time_requirement.strftime('%m-%d-%y'), #gotta convert to string
                        "short":'true'
                        },
                        {
                        "title":"ID",
                        "value":req.friendly_id,
                        "short":'true'
                        },
                        {
                        "title":"Priority",
                        "value":req.priority,
                        "short":'true'
                        },
                        {
                        "title":"Summary",
                        "value":req.summary,
                        }
                    ]
                }
            ]
            }
        
        send_webhook(wh_data, hooks)
        
    #adding consumers from tagify
    delete_requirement_consumer_links(req_id=req.id)
    org_id=User.query.filter_by(id=current_user.id).first().organization
    add_requirement_consumer_links(requirement_ids=[req.id], consumer_ids=consumer_ids_from_tagify(form_data.get('consumers'), org_id))

    return redirect(url_for('list_reqs'))

@app.route('/req/<req_id>')
@login_required
def view_req(req_id):
    req_info = Requirements.query.filter_by(id=req_id).first()
    consumers=db.session.query(Consumers, RequirementConsumers).join(RequirementConsumers, Consumers.id==RequirementConsumers.consumer).join(User, User.organization==Consumers.organization).filter(RequirementConsumers.requirement == req_id).all()
    final_consumers=[consumer.name for consumer,rc in consumers]
    

    linked_reports=db.session.query(Reports, RequirementReports).join(RequirementReports, Reports.id==RequirementReports.report).filter(RequirementReports.requirement==req_id).all()
    final_list=[report for report, rr in linked_reports]
    if request.args.get('pdf'):
        html=render_template('pdf_ir.html',req_info=req_info,final_list=final_list,final_consumers=final_consumers, comments=get_comments(req_id=req_id), user_id=current_user.id, ir_date=datetime.now())
        pdf_file = HTML(string=html).write_pdf()
        response = Response(pdf_file, content_type='application/pdf')
        fname='{}.pdf'.format(req_info['friendly_id'].replace('.','_'))
        response.headers.set('Content-Disposition', 'attachment', filename=fname)
        
        return response

    return render_template('ir.html',req_info=req_info,page_title=req_info.title,final_list=final_list,final_consumers=final_consumers, comments=get_comments(req_id=req_id), user_id=current_user.id)

            
def add_requirement_consumer_links(requirement_ids=[], consumer_ids=[]):
    for requirement_id in requirement_ids:
        for consumer_id in consumer_ids:
            rec=RequirementConsumers(requirement=requirement_id, consumer=consumer_id)
            add_db_entry(rec)

def delete_requirement_consumer_links(req_id=None, consumer_id=None):
    if req_id:
        RequirementConsumers.query.filter(RequirementConsumers.requirement == req_id).delete()
        db.session.commit()
    if consumer_id:
        RequirementConsumers.query.filter(RequirementConsumers.consumer == consumer_id).delete()
        db.session.commit()



'''
This will add the consumer record for that org if not in there and will return all the consumer ids
'''
def consumer_ids_from_tagify(consumer_string, org_id):
    if consumer_string:
        
        consumer_list=json.loads(consumer_string)
        consumer_vals=[x['value'] for x in consumer_list]
        if len(consumer_vals)> 0:
            consumer_dict={}
            consumers=Consumers.query.filter_by(organization=org_id).all()
            for consumer in consumers:
                consumer_dict[consumer.name]=consumer.id
            
            for val in consumer_vals:
                if val not in consumer_dict:
                    consumer_record=Consumers(name=val, organization=org_id)
                    add_db_entry(consumer_record)
                    consumer_dict[val]=consumer_record.id
    
        return [id for name, id in consumer_dict.items() if name in consumer_vals]
    else:
        return []

