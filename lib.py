'''
Library of functions called by different modules
'''
from flask import jsonify
from flask_login import current_user
import re
import json
from config import db
from models import Comments, User, Organization, Indicators, Links
from sqlalchemy import func, asc, desc
from datetime import datetime, timedelta
import json
import requests
import logging

IP_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
DOMAIN_REGEX = r'(?:(?:[\da-zA-Z])(?:[_\w-]{,62})\.){,127}(?:(?:[\da-zA-Z])[_\w-]{,61})?(?:[\da-zA-Z]\.(?:(?:xn\-\-[a-zA-Z\d]+)|(?:[a-zA-Z\d]{2,})))'
EMAIL_REGEX = r'\S+@\S+\.\S+'
SHA_REGEX = r'[A-Fa-f0-9]{64}'
SHA512_REGEX = r'[A-Fa-f0-9]{128}'
MD5_REGEX = r'[A-Fa-f0-9]{32}'
ATTACK_REGEX = r'T\d{4}'
URL_REGEX = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
CVE_REGEX = r'CVE\-\d{4}\-\w+'


INDICATOR_REGEX = {
    'IP': IP_REGEX,
    'Domain': DOMAIN_REGEX,
    'MITRE ATT&CK Technique': ATTACK_REGEX,
    'SHA256 Hash': SHA_REGEX,
    'Email': EMAIL_REGEX,
    'MD5 Hash': MD5_REGEX,
    'SHA512 Hash': SHA512_REGEX,
    'URL': URL_REGEX,
    'CVE': CVE_REGEX,
}


def add_db_entry(entry):
    db.session.add(entry)
    db.session.commit()

def send_webhook(message, urls=[]):
    """
    Sends a webhook message to a list of URLs.

    Args:
        message (dict or str): The message to send. If a string is provided, it will be wrapped in a 'text' field.
        urls (list): List of webhook URLs to send the message to.
    """
    # Create a session for making requests
    session = requests.Session()

    for url in urls:
        if isinstance(message, dict):
            wh_data = message
        else:
            wh_data = {'text': message}

        try:
            response = session.post(
                url,
                json=wh_data,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()  # Raise an exception for HTTP errors

            logging.info('Webhook sent to %s. %s', url, wh_data)
        except requests.exceptions.RequestException as err:
            logging.error('Webhook error sending message "%s" to url %s. %s', wh_data, url, err)

    # Close the session
    session.close()

def get_comments(req_id=None, report_id=None, indicator_id=None):
    # Create a base query for Comments with an optional filter
    base_query = db.session.query(Comments, User.name).join(User, User.id == Comments.user)
    
    if report_id:
        base_query = base_query.filter(Comments.report == report_id)

    if indicator_id:
        base_query = base_query.filter(Comments.indicator == indicator_id)

    if req_id:
        base_query = base_query.filter(Comments.requirement == req_id)

    # Order the comments by updated_at in descending order
    comments_data = (
        base_query
        .order_by(desc(Comments.updated_at))
        .all()
    )

    # Convert the result into a list of dictionaries
    return [
        {
            'id': comm.id,
            'comment': comm.comment,
            'created_at': comm.created_at,
            'updated_at': comm.updated_at,
            'user': user
        }
        for comm, user in comments_data
    ]
'''
returns info on user
'''
def get_user_info(user_id):
    user_info = {}
    user = db.session.query(User).filter_by(id=user_id).first()

    # Return early if the user is not found
    if not user:
        return user_info

    org = db.session.query(Organization).filter_by(id=user.organization).first()

    user_info = {
        **user.__dict__,  # Copy user fields to user_info
        'whois_enabled': org.whois_enabled,
        'ipinfo_enabled': org.ipinfo_enabled,
        'vt_enabled': org.vt_enabled,
        'shodan_enabled': org.shodan_enabled,
        'emailrep_enabled': org.emailrep_enabled,
        'av_enabled': org.av_enabled,
        'gn_enabled': org.gn_enabled,
        'riskiq_enabled': org.riskiq_enabled,
        'urlscan_enabled': org.urlscan_enabled,
        'misp_enabled': org.misp_enabled,
        'hibp_enabled': org.hibp_enabled,
        'hunter_enabled': org.hunter_enabled,
    }

    if user.role == 'admin':
        user_info.update({
            'vt_api_key': org.vt_api_key,
            'shodan_api_key': org.shodan_api_key,
            'emailrep_api_key': org.emailrep_api_key,
            'av_api_key': org.av_api_key,
            'gn_api_key': org.gn_api_key,
            'riskiq_api_key': org.riskiq_api_key,
            'riskiq_username': org.riskiq_username,
            'urlscan_api_key': org.urlscan_api_key,
            'misp_api_key': org.misp_api_key,
            'misp_url': org.misp_url,
            'hibp_api_key': org.hibp_api_key,
            'hunter_api_key': org.hunter_api_key,
        })

    return user_info



'''
returns 
minutes ago if < hour
hours ago if < day
days ago if < week
weeks ago if < month
months ago if < year
else years ago
'''
def time_ago(time):
    diff_seconds=(datetime.now() - time).total_seconds()
    MINUTE=60
    HOUR=MINUTE*60
    DAY=HOUR*24
    WEEK=DAY*7
    MONTH=DAY*30
    YEAR=DAY*365
    
    if diff_seconds < MINUTE:
        return ('Just now')
    elif diff_seconds < HOUR:
        if diff_seconds/MINUTE ==1:
            return '1 minute ago'
        else:
            return '{0:.0f} minutes ago'.format(diff_seconds/MINUTE)
    elif diff_seconds < DAY:
        if round(diff_seconds/HOUR) ==1:
            return '1 hour ago'
        else:
            return '{0:.0f} hours ago'.format(diff_seconds/HOUR)
    elif diff_seconds < WEEK:
        if round(diff_seconds/DAY) ==1:
            return '1 day ago'
        else:
            return '{0:.0f} days ago'.format(diff_seconds/DAY)
    elif diff_seconds < MONTH:
        if round(diff_seconds/WEEK) ==1:
            return '1 week ago'
        else:
            return '{0:.0f} weeks ago'.format(diff_seconds/WEEK)
    elif diff_seconds < YEAR:
        if round(diff_seconds/MONTH) ==1:
            return '1 month ago'
        else:
            return '{0:.0f} months ago'.format(diff_seconds/MONTH)
    else:
        return '{0:.1f} years ago'.format(diff_seconds/YEAR)

'''
Don't create a link for that indicator/report combo already in there - will save on database space
'''
def link_exists(new_link):
    link=Links.query.filter_by(indicator=new_link.indicator).filter_by(report=new_link.report).first()
    
    return link != None

'''
Escape out characters so jquery works
'''
def escape_jquery(value):
    escape_chars='!"#$%&\'()*+,./:;<=>?@[\\]^``{|}~'
    for char in escape_chars:
        value=value.replace(char, '__')
    else:
        return value


'''
parse out the indicators in a report, save record linking indicator to a report, and 
put them in queue to be enriched.
'''
def parse_indicators(summary, report_id, queue):
    org_id = User.query.filter_by(id=current_user.id).first().organization

    # Initialize a dictionary to store indicator IDs
    indicator_ids = {}

    # Iterate through indicator types and their corresponding regular expressions
    for indicator_type, regex_pattern in INDICATOR_REGEX.items():
        matches = re.findall(regex_pattern, summary)

        for match in matches:
            # Check if the indicator already exists in the database
            match_check = Indicators.query.filter_by(indicator=match).first()

            if match_check:
                indicator_ids[match_check.id] = match
            else:
                # Indicator doesn't exist, create a new indicator and link it
                new_indicator = Indicators(indicator=match, indicator_type=indicator_type)
                add_db_entry(new_indicator)
                indicator_ids[new_indicator.id] = match

    # Iterate through the indicator IDs and create links
    for id, match in indicator_ids.items():
        # Kickoff a task to enrich the new indicator
        job = queue.enqueue('main.enrich_pipeline', json.dumps({'indicator': str(match), 'organization': org_id}))
        new_link = Links(indicator=id, report=report_id, kill_chain='Unknown', diamond_model='Unknown', confidence='Low')
        
        if not link_exists(new_link):
            add_db_entry(new_link)