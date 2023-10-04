from flask import  render_template, request, redirect, flash, url_for, jsonify, abort, Response
from flask_login import login_required, current_user
from models import Indicators,  Reports, Links, User
from lib import add_db_entry, get_comments, get_user_info
from main import app, parse_indicators, queue
from config import db
import logging
from sqlalchemy import func, asc, desc


@app.route('/indicators', methods=['GET'])
@login_required
def view_indicators():
    try:
        indicators = Indicators.query.all()
    except Exception as e:
        # Log the exception for debugging
        app.logger.error(f"Error retrieving indicators: {e}")
        # You could return a custom error page or message
        return "Error retrieving indicators. Please try again later.", 500

    # If you decide on how to handle confidence and kill_chain, you can process them here
    # For now, we'll just pass them to the template

    return render_template('indicators.html', indicators=indicators, page_title="Indicators")


@app.route('/refresh_indicator/<indicator_id>/<report_id>')
@login_required
def refresh_indicator(indicator_id, report_id):
    try:
        indicator_info = Indicators.query.filter_by(id=indicator_id).all()
        result_dict = [u.__dict__ for u in indicator_info]

        # Log a message indicating that the refresh process has started
        app.logger.info(f"Refreshing indicator {indicator_id} for report {report_id}")

        parse_indicators(str(result_dict[0]['indicator']), report_id, queue)

        # Log a message indicating that the refresh process was successful
        app.logger.info(f"Indicator {indicator_id} refreshed successfully for report {report_id}")

    except Exception as e:
        # Log the exception for debugging
        app.logger.error(f"Error refreshing indicator with ID {indicator_id} for report {report_id}: {e}")
        # You could return a custom error page or message
        return "Error refreshing indicator. Please try again later.", 500

    # Redirect to the report using Flask's url_for function
    return redirect('/report/' + report_id)
    
@app.route('/edit_indicator/<int:indicator_id>')
@login_required
def edit_indicator(indicator_id):
    # Fetch the specific indicator by its ID
    indicator = Indicators.query.filter_by(id=indicator_id).first()

    # Ensure the indicator was found
    if not indicator:
        abort(404, description="Indicator not found.")

    related_reports = get_related_reports(indicator_id)

    return render_template(
        'edit_indicator.html',
        indicator=indicator.as_dict(),  # assume you've a method to get the details as a dict
        comments=get_comments(indicator_id=indicator_id),
        related_reports=related_reports,
        user_info=get_user_info(current_user.id),
        user_id=current_user.id,
        page_title=indicator.indicator
    )

def get_related_reports(indicator_id):
    """Fetch related reports for a given indicator."""
    links = (
        db.session.query(Reports, Links)
        .join(Links, Links.report == Reports.id)
        .filter(Links.indicator == indicator_id)
        .order_by(desc(Reports.updated_at))
        .all()
    )

    reports_list = []
    for report, link in links:
        rep = {
            'id': report.id,
            'title': report.title,
            # ... add other needed attributes
            'confidence': link.confidence,
            'kill_chain': link.kill_chain,
            'diamond_model': link.diamond_model
        }
        reports_list.append(rep)

    return reports_list

@app.route('/update_indicator/<indicator_id>/<report_id>', methods=['POST'])
@login_required
def update_indicator(indicator_id, report_id):
    form_data = request.form
    report_indicator = Links.query.filter_by(report=report_id, indicator=indicator_id).first()
    
    try:
        if report_indicator:
            update_report_link_from_form(report_indicator, form_data)
        else:
            create_new_report_link(report_id, indicator_id, form_data)

        db.session.commit()
        return jsonify(status='success'), 200

    except Exception as e:
        # Consider using a logging library here to log the exception details
        return jsonify(status='error', message=str(e)), 500


def update_report_link_from_form(report_indicator, form_data):
    """Update report link attributes from form data."""
    if 'kill_chain' in form_data:
        report_indicator.kill_chain = form_data['kill_chain']
    
    if 'confidence' in form_data:
        report_indicator.confidence = form_data['confidence']
    
    if 'diamond_model' in form_data:
        report_indicator.diamond_model = form_data['diamond_model']


def create_new_report_link(report_id, indicator_id, form_data):
    """Create a new report link from form data."""
    new_report_indicator = Links(report=report_id, indicator=indicator_id)
    new_report_indicator.kill_chain = form_data.get('kill_chain', 'Unknown')
    new_report_indicator.confidence = form_data.get('confidence', 'Low')
    new_report_indicator.diamond_model = form_data.get('diamond_model', 'Unknown')
    db.session.add(new_report_indicator)