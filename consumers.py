from flask import  render_template, request, redirect, flash, url_for, jsonify, abort, Response
from flask_login import login_required, current_user
from models import Requirements, RequirementConsumers, User, Consumers,RequirementReports, Reports
from lib import add_db_entry
from main import app
from config import db
from sqlalchemy import func, asc, desc, exc
import logging


@app.route('/consumers', methods=['GET'])
@login_required
def view_consumers():
    try:
        # Getting organization ID
        org_id = User.query.filter_by(id=current_user.id).first().organization

        # Retrieving and processing consumers
        consumers = Consumers.query.filter_by(organization=org_id).all()
        consumer_dict = {consumer.id: {**consumer.__dict__} for consumer in consumers}
        for key in consumer_dict:
            consumer_dict[key].pop('_sa_instance_state', None)
            consumer_dict[key]['num_of_reports'] = 0
            consumer_dict[key]['num_of_reqs'] = 0

        # Processing intel reports counts
        process_counts(RequirementConsumers, Requirements, 'num_of_reqs', 'oldest_req', 'latest_req', consumer_dict)
        
        # Processing report counts
        process_counts(RequirementConsumers, Reports, 'num_of_reports', 'oldest_report', 'latest_report', consumer_dict, join_model=RequirementReports)

        return render_template('consumers.html', consumers=consumer_dict.values(), page_title='Consumers')
    except Exception as e:
        app.logger.error(f"Error in view_consumers: {str(e)}")
        return "An unexpected error occurred.", 500

def process_counts(main_model, secondary_model, count_field, min_date_field, max_date_field, consumer_dict, join_model=None):
    try:
    # Building the query
        query = (db.session.query(main_model.consumer, func.count(secondary_model.id), func.min(secondary_model.created_at), func.max(secondary_model.updated_at))
                .join(secondary_model, main_model.requirement == secondary_model.id)
                .filter(main_model.consumer.in_(consumer_dict.keys()))
                .group_by(main_model.consumer))

        if join_model:
            query = query.join(join_model, join_model.requirement == main_model.requirement)

        results = query.all()
        for result in results:
            consumer = consumer_dict.get(result[0], {})
            consumer[count_field] = result[1]
            consumer[min_date_field] = result[2]
            consumer[max_date_field] = result[3]
    except Exception as e:
        app.logger.error(f"Error in process_counts: {str(e)}")

@app.route('/edit_consumer/<consumer_id>')
@login_required
def edit_consumer(consumer_id):
    try:
        consumer = Consumers.query.filter_by(id=consumer_id).first()
        return render_template('edit_consumer.html',consumer=consumer)
    except Exception as e:
        app.logger.error(f"Error in edit_consumer: {str(e)}")


@app.route('/edit_consumer/<consumer_id>',methods=['POST'])
@login_required
def update_consumer(consumer_id):
    try:
        args = request.form
        subtitle = args.get('subtitle')
        email = args.get('email')
        poc = args.get('poc')
        Consumers.query.filter_by(id=consumer_id).update({'subtitle':subtitle,'email':email,'poc':poc})
        db.session.commit()
        db.session.flush()
        return redirect('/consumers')
    except Exception as e:
        app.logger.error(f"Error in update_consumer: {str(e)}")
