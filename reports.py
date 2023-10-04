from flask import  render_template, request, redirect, flash, url_for, jsonify, abort, Response
from flask_login import login_required, current_user
from flask_weasyprint import HTML, render_pdf
import re
import json
from markdown2 import Markdown
from io import StringIO
from models import Links, Reports, Organization, Requirements, RequirementReports, RequirementConsumers, Indicators, ReportTags, User, Organization
from lib import IP_REGEX, DOMAIN_REGEX,EMAIL_REGEX,SHA_REGEX,SHA512_REGEX,MD5_REGEX,ATTACK_REGEX, URL_REGEX, CVE_REGEX
from lib import add_db_entry, get_comments,  get_user_info, escape_jquery, parse_indicators, send_webhook
from main import app, queue
from config import db
from enrichers import export_to_misp
from datetime import datetime
from sqlalchemy import func, asc, desc

from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute

@app.route('/active_reports')
@app.route('/active_reports/<consumer_id>')
@login_required
def active_reports(consumer_id=None):
    return list_reports(consumer_id)

@app.route('/list_reports')
@app.route('/list_reports/<consumer_id>')
@login_required
def list_reports(consumer_id=None):
    show_archived=request.args.get('show_archived', False)=='True'
    if show_archived:
        if consumer_id:        
            reports=(db.session.query(Reports)
                .join(RequirementReports, RequirementReports.report==Reports.id)
                .join(RequirementConsumers, RequirementConsumers.requirement==RequirementReports.requirement)
                .filter(RequirementConsumers.consumer==consumer_id)
                .all())
        elif request.args.get('tag'):
            reports=(db.session.query(Reports)
                .join(ReportTags, ReportTags.report==Reports.id)
                .filter(func.lower(ReportTags.tag) == func.lower(request.args.get('tag')))
                .all())        
        else:
            reports = Reports.query.all()
    else:
        if consumer_id:        
            reports=(db.session.query(Reports)
                .join(RequirementReports, RequirementReports.report==Reports.id)
                .join(RequirementConsumers, RequirementConsumers.requirement==RequirementReports.requirement)
                .filter(RequirementConsumers.consumer==consumer_id)
                .filter(Reports.is_archived.is_(False))
                .all())
        elif request.args.get('tag'):
            reports=(db.session.query(Reports)
                .join(ReportTags, ReportTags.report==Reports.id)
                .filter(Reports.is_archived.is_(False))
                .filter(func.lower(ReportTags.tag) == func.lower(request.args.get('tag')))
                .all())        
        else:
            reports = Reports.query.filter(Reports.is_archived.is_(False)).all()
        
    return render_template('active_reports.html',reports=reports, tag=request.args.get('tag'), page_title="Reports", show_archived=show_archived)

@app.route('/archive_report/<report_id>',methods=['GET', 'POST'])
@login_required
def archive_report(report_id):
    report = Reports.query.filter_by(id=report_id).first()
    report.is_archived=True
    db.session.commit()
    db.session.flush()
    flash('Report archived.')
    return redirect(url_for(request.args.get('landing', 'edit_report'), report_id=report_id))


@app.route('/unarchive_report/<report_id>',methods=['GET', 'POST'])
@login_required
def unarchive_report(report_id):
    report = Reports.query.filter_by(id=report_id).first()
    report.is_archived=False
    db.session.commit()
    db.session.flush()
    flash('Report archived.')
    return redirect(url_for(request.args.get('landing', 'edit_report'), report_id=report_id))

#@app.route('/archived_reqs')


@app.route('/delete_report/<report_id>')
@login_required
def delete_report(report_id):
    Links.query.filter_by(report=report_id).delete()
    RequirementReports.query.filter_by(report=report_id).delete()

    Reports.query.filter_by(id=report_id).delete()
    db.session.commit() 
    return redirect('/active_reports')

@app.route('/edit_report/<report_id>')
@login_required
def edit_report(report_id):
    report_info = Reports.query.filter_by(id=report_id).first()
    result_dict = report_info.__dict__ 
    edit = True
    
    all_reqs = db.session.query(Requirements).filter(Requirements.is_archived.is_(False)).all()
    
    linked_requirements=db.session.query(Requirements).join(RequirementReports, RequirementReports.requirement==Requirements.id).filter(RequirementReports.report==report_id).all()
    linked_list=[req.id for req in linked_requirements]
    reqs=[]
    for req in all_reqs:
        r=req.__dict__
        if req.id in linked_list:
            r['selected']='selected'
        reqs.append(r)
#    linked_reqs = db.session.query(Reports.linked_reqs).filter(Reports.id == report_id).all()
#    linked_list = linked_reqs[0][0].split("-")
    tlp = ['WHITE','GREEN','AMBER','RED']
    tags=ReportTags.query.filter_by(report=report_id).order_by(ReportTags.tag).all()
    if len(tags) > 0:
        result_dict['tags']=', '.join([rt.tag for rt in tags])
    else:
        result_dict['tags']=''
    return render_template('new_report.html',report_info=result_dict, edit=edit,all_reqs=all_reqs,tlp=tlp,page_title="Edit Report")


@app.route('/new_report')
@login_required
def new_report():
    all_reqs = db.session.query(Requirements.id, Requirements.friendly_id, Requirements.title).filter(Requirements.is_archived.is_(False)).all()
    tlp = ['WHITE','GREEN','AMBER','RED']
    report_info = [{'tlp':'WHITE'}]
    
    return render_template('new_report.html',all_reqs=all_reqs,tlp=tlp,report_info=report_info,page_title="New Report")


@app.route('/submit_report', methods=['POST'])
@login_required
def submit_report():
    print('sub')
    linked_reqs = request.form.getlist('linked_reqs')
    consumers = request.form.get('consumers')
    #form_data = request.form
    summary=request.form.get('summary','')
    summary=unmark_indicators(summary)
    #getting rid of pesky dashes
    for i in range(8210, 8214):
        summary=summary.replace(chr(i),'-')
    
    if request.form.get('is_edited'):
        tlp = request.form.get('tlp')
        report= Reports.query.filter_by(id=request.form.get('id')).first()
        report.title=request.form.get('title')
        report.content=summary
        report.friendly_id=request.form.get('friendly_id')
        #report.tags=request.form.get('tags')
        report.is_archived=request.form.get('is_archived')
        if report.is_archived:
            report.is_archived = 1
        else:
            report.is_archived = 0
        report.tlp=tlp
        db.session.commit()
        db.session.flush()
        goto=url_for('view_report', report_id=report.id)
        
    else:
        title = request.form.get('title')
        friendly_id = request.form.get('friendly_id')
        #tags = request.form.get('tags')
        tlp = request.form.get('tlp')
        report = Reports(title=title, content=summary,creator=current_user.name,friendly_id=friendly_id,is_archived=False,tlp=tlp)
        add_db_entry(report)
        goto=url_for('active_reports')
        
        #send a webhook
        hooks=Organization.query.filter(Organization.slack_webhook_on_report_create.is_(True)).all()
        hooks=[hook.slack_webhook for hook in hooks if hook.slack_webhook]
        
        message='A new report, {},  has been created. To view the report, go to: {}{}'.format(report.title,request.host_url[0:-1], url_for('view_report', report_id=report.id))
        wh_data = {
            "attachments":[
                {
                    "fallback":message,
                    "pretext":message,
                    "color":"#6658EA",
                    "fields":[
                        {
                        "title":"Writer",
                        "value":report.creator,
                        "short":'true'
                        },
                        {
                        "title":"ID",
                        "value":report.friendly_id,
                        "short":'true'
                        },
                        {
                        "title":"Title",
                        "value":report.title,
                        }
                    ]
                }
            ]
            }
        
        send_webhook(wh_data, hooks)

        
    ReportTags.query.filter(ReportTags.report == report.id).delete()

    if request.form.get('tags'):
        tag_list=json.loads(request.form.get('tags'))
        for tag in tag_list:
            rt=ReportTags(report=report.id, tag=tag['value'])
            add_db_entry(rt)
            
    parse_indicators(summary,report.id, queue)
    delete_report_requirement_links(report_id=report.id)
    add_report_requirement_links(report_ids=[report.id], req_ids=linked_reqs)
    
    return redirect(goto)

@app.route('/report/<report_id>')
@login_required
def view_report(report_id):
    report_info = Reports.query.filter_by(id=report_id).first()
    content=report_info.content
    for i in range(8210, 8214):
        content=content.replace(chr(i),'-')

    '''
    This marks up domains, emails, ip addresses and hashes with different html classes
    '''
    ip_class='marked marked-ip'#'btn btn-bold btn-sm btn-font-sm btn-label-success btn-clickable'
    email_class='marked marked-email'#'btn btn-bold btn-sm btn-font-sm btn-label-warning btn-clickable'#
    domain_class='marked marked-domain'#'btn btn-bold btn-sm btn-font-sm btn-label-danger btn-clickable'
    hash_class='marked marked-hash'#'btn btn-bold btn-sm btn-font-sm btn-label-brand btn-clickable'
    attack_class='marked marked-attack'#'btn btn-bold btn-sm btn-font-sm btn-label-brand btn-clickable'
    md5_class='marked marked-hash'#'btn btn-bold btn-sm btn-font-sm btn-label-brand btn-clickable'
    sha512_class='marked marked-hash'#'btn btn-bold btn-sm btn-font-sm btn-label-brand btn-clickable'
    url_class='marked marked-url'#'btn btn-bold btn-sm btn-font-sm btn-label-brand btn-clickable'
    cve_class='marked marked-cve'#'btn btn-bold btn-sm btn-font-sm btn-label-brand btn-clickable'

    ip_list = re.findall(IP_REGEX, content)
    email_list=re.findall(EMAIL_REGEX, content)    
    domain_list=re.findall(DOMAIN_REGEX, content)
    hash_list=re.findall(SHA_REGEX, content)    
    attack_list=re.findall(ATTACK_REGEX, content)    
    md5_list=re.findall(MD5_REGEX, content)    
    sha512_list=re.findall(SHA512_REGEX, content)    
    url_list=re.findall(URL_REGEX,content)
    cve_list=re.findall(CVE_REGEX,content)
    
    indicator_dict={}
    
    # Get all indicators that are in the current report by matching the Links table to the Indicators table
    indicators = db.session.query(Indicators).join(Links, Indicators.id == Links.indicator).join(Reports, Links.report == Reports.id).filter(Reports.id == report_id).all()
    for indicator in indicators:
        indicator_dict[indicator.id]=indicator.__dict__
    indicators = db.session.query(Indicators).filter(Indicators.indicator.in_(email_list + ip_list + hash_list + domain_list + md5_list + sha512_list + url_list + cve_list)).all()
    for indicator in indicators:
        indicator_dict[indicator.id]=indicator.__dict__

    #getting kill_chain, confidence, diamond_model for each indicator_report
    links=(db.session.query(Links)
           .filter(Links.indicator.in_(indicator_dict.keys()))
           .filter(Links.report==report_id)
           .all())
    for link in links:
        indicator=indicator_dict.get(link.indicator, {})
        indicator['kill_chain']=link.kill_chain
        indicator['diamond_model']=link.diamond_model
        indicator['confidence']=link.confidence
        indicator_dict[link.indicator]=indicator

    indicator_counts={}
    
    also_added=False
    additional_inds='';
  
    for indicator in indicator_dict.values():
        if indicator['indicator'] not in email_list + ip_list + hash_list + domain_list + attack_list + md5_list + sha512_list + url_list + cve_list:
            #todo marking them up and putting id
            if indicator['indicator_type']=='IP':
                style=ip_class
            elif indicator['indicator_type']=='SHA256 Hash':
                style=hash_class
            elif indicator['indicator_type']=='MD5 Hash':
                style=hash_class
            elif indicator['indicator_type']=='SHA512 Hash':
                style=hash_class
            elif indicator['indicator_type']=='Email':
                style=email_class
            elif indicator['indicator_type']=='Domain':
                style=domain_class
            elif indicator['indicator_type']=='MITRE ATT&CK Technique':
                style=attack_class
            elif indicator['indicator_type']=='URL':
                style=url_class
            elif indicator['indicator_type']=='CVE':
                style=cve_class
            else:
                style=email_class
                
            #if not also_added:
            #    additional_inds='{}<br/>Also linked to this report: '.format(additional_inds)
            #additional_inds='{}<span class="{}" id="{}{}">{}</span> '.format(additional_inds, style, indicator['indicator'].replace('.','__').replace('@', '_'),indicator_counts.get(indicator['indicator'],0),indicator['indicator'])
            indicator_counts[indicator['indicator']]=indicator_counts.get(indicator['indicator'],0)+1

        indicator.pop('_sa_instance_state')
        indicator_dict[indicator['id']]=indicator

    new_content=''

    line=content.split('\n')
    reg=r'^#{1,6}\s*.*'
    for line in line:
        for matchedtext in re.findall(reg, line):
            level=matchedtext.count('#')
            find=matchedtext
            rep='<h{}>{}</h{}>'.format(level, find.replace('#',''), level)
            content=content.replace(find, rep)

    #search=re.split(r'(\s+)', content)
    is_code=False
    lines=content.split('\n')
    for line in lines:
        search=line.split()
        regexp = re.compile(r'\S+')
        for word in search:
            if regexp.search(word):
                
                search_word=word
                if word[-1] in (':', ',', '.',','):
                    search_word=word[0:-1]
                    delim=word[-1]
                else:
                    delim=' '
                    
                if word=='```':
                    is_code= (not is_code)
                    #if is_code:
                    #    new_content='{}<pre><code>'.format(new_content)
                    #else:
                    #    new_content='{}</code></pre>'.format(new_content)
                #elif is_code:
                if is_code:
                    new_content='{}{}{} '.format(new_content,word,delim)
                else:
                    txt=search_word
                    regex=re.compile(r'\(\S+\)')
                    if regex.match(search_word):
                        txt=re.search(r'\((.*?)\)',txt).group(1)
                        
                    if search_word in ip_list:
                        new_content='{}<span class="{}" id="{}{}">{}</span>{} '.format(new_content, ip_class, escape_jquery(txt),indicator_counts.get(txt,0), search_word,delim)
                    elif search_word in email_list:
                        new_content='{}<span class="{}" id="{}{}">{}</span>{} '.format(new_content, email_class, escape_jquery(txt), indicator_counts.get(txt,0),search_word,delim)
                    elif search_word in domain_list and word not in email_list + ip_list:
                        new_content='{}<span class="{}" id="{}{}">{}</span>{} '.format(new_content, domain_class,escape_jquery(txt), indicator_counts.get(txt,0),search_word,delim)
                    elif search_word in sha512_list:
                        new_content='{}<span class="{}" id="{}{}">{}</span>{} '.format(new_content, hash_class, escape_jquery(txt),indicator_counts.get(txt,0), search_word,delim)
                    elif search_word in hash_list:
                        new_content='{}<span class="{}" id="{}{}">{}</span>{} '.format(new_content, hash_class, escape_jquery(txt),indicator_counts.get(txt,0), search_word,delim)
                    elif search_word in md5_list:
                        new_content='{}<span class="{}" id="{}{}">{}</span>{} '.format(new_content, hash_class, escape_jquery(txt),indicator_counts.get(txt,0), search_word,delim)
                    elif search_word in attack_list:
                        new_content='{}<span class="{}" id="{}{}">{}</span>{} '.format(new_content, attack_class, escape_jquery(txt),indicator_counts.get(txt,0), search_word,delim)
                    elif search_word in url_list:
                        new_content='{}<span class="{}" id="{}{}">{}</span>{} '.format(new_content, url_class, escape_jquery(txt),indicator_counts.get(txt,0), search_word,delim)
                    elif search_word in cve_list:
                        new_content='{}<span class="{}" id="{}{}">{}</span>{} '.format(new_content, cve_class, escape_jquery(txt),indicator_counts.get(txt,0), search_word,delim)
                    else:
                        new_content='{}{}{} '.format(new_content,search_word,delim)
        
                    if search_word in ip_list + email_list + domain_list + hash_list + attack_list + md5_list + sha512_list + url_list + cve_list:
                        indicator_counts[txt]=indicator_counts.get(txt,0)+1
                
            else:
                new_content='{} {}'.format(new_content, word)
                #new_content='{}{}'.format(new_content,word.replace('\r\n', '<br/>').replace('\r', '<br/>').replace('\n', '<br/>'))
        if is_code:
            new_content='{}\r\n'.format(new_content)
        else:
            new_content='{}<br/>'.format(new_content)
            
            
    content=new_content
    markdowner = Markdown()
    content=markdowner.convert(content)
    #content=content.replace('. ', '<br/>')
    #content=content.replace(': ', '<br/>')
    #content=content+additional_inds
    
    #content=markdown(content)
    #replace markdowns line breaks in code- mine are <br/>
    #content=content.replace('<br>', '')
    #not sure why this isn't searching and replacing
    #content=content.replace('<code>', '<pre><code>')
    #content=content.replace('</code>', '</code></pre>')

    #print(content)
    
    #content=content.replace('\r\n', '<br/>').replace('\r', '<br/>').replace('\n', '<br/>')    
    links = db.session.query(Reports, Links).join(Links, Reports.id == Links.report).filter(Links.report != report_id).filter(Links.indicator.in_(indicator_dict.keys())).all()
    for(report, link) in links:  
        indicator_record=indicator_dict.get(link.indicator)
        if indicator_record:
            #get related report dict if in there, else make a new dict- a dict will prevent dupes
            report_list=indicator_record.get("related_reports",{})
        
            #only include related reports if the title is not blank and id not the report's id
            if report.title != '' and report.id != int(report_id):
                #report_list[report.id]=report.__dict__
                report_list[report.id]={'id':report.id, 'title':report.title, 'friendly_id':report.friendly_id}
            indicator_record["related_reports"]=report_list
            indicator_dict[link.indicator]=indicator_record
    #user_details = User.query.filter_by(id=current_user.id).all()
    #user_dict = [u.__dict__ for u in user_details]
    
    comments=get_comments(report_id=report_id)
    report_info=report_info.__dict__
    tags=ReportTags.query.filter_by(report=report_id).order_by(ReportTags.tag).all()
    # if len(tags) > 0:
    #     report_info['tags']=', '.join([rt.tag for rt in tags])
    # else:
    #     report_info['tags']=''

    if request.args.get('pdf'):
        #Don't know what this is but commenting out...
        #return render_template('blog-post-cover.html',page_title=report_info['title'],report_info=report_info, indicator_counts=indicator_counts,new_content=content, indicators=indicator_dict.values(), user_info=get_user_info(current_user.id), comments=comments, tags=tags, report_date=datetime.now())
        
        html=render_template('blog-post-cover.html',report_info=report_info, indicator_counts=indicator_counts,new_content=content, indicators=indicator_dict.values(), user_info=get_user_info(current_user.id), comments=comments, tags=tags, report_date=datetime.now())
        pdf_file = HTML(string=html).write_pdf()
        response = Response(pdf_file, content_type='application/pdf')
        fname='{}.pdf'.format(report_info['friendly_id'].replace('.','_'))
        response.headers.set('Content-Disposition', 'attachment', filename=fname)
        
        return response
        
    else:
        return render_template('report.html',page_title=report_info['title'],report_info=report_info, indicator_counts=indicator_counts,new_content=content, indicators=indicator_dict.values(), user_info=get_user_info(current_user.id), comments=comments, tags=tags)


def add_report_requirement_links(report_ids=[], req_ids=[]):
    for report_id in report_ids:
        for req_id in req_ids:
            rec=RequirementReports(report=report_id, requirement=req_id)
            add_db_entry(rec)
    
def delete_report_requirement_links(report_id=None, req_id=None):
    if report_id:
        RequirementReports.query.filter(RequirementReports.report == report_id).delete()
        db.session.commit()
    if req_id:
        RequirementReports.query.filter(RequirementReports.requirement == req_id).delete()
        db.session.commit()
'''
This removes markdown tags from indicators
'''
def unmark_indicators(content):
    
    #step 1 undo link markdowns 
    reg = r'\[([^\]]*)\]\(([^)]*)\)'
    for matchedtext in re.findall(reg, content):
        if len(matchedtext) > 1:
            if matchedtext[1]:
                rep= matchedtext[1]
            else:
                rep= matchedtext[0]
            content=content.replace('[{}]({})'.format(matchedtext[0],matchedtext[1]),rep)    
    markdown_re=[
         [r'(?<=\*\*).*?(?=\*\*)', '**{}**'],#bold markdown
         [r'(?<=_)(.*?)(?=_)', '_{}_'],#italic markdown
         [r'(?<=\#\#\#\s)(.*?)\s','### {}'] # heading markdown
         ]

    for item in markdown_re:
        expr1=item[0]
        expr3=item[1]
        for matchedtext in re.findall(expr1, content):
            for expr2 in (IP_REGEX,DOMAIN_REGEX,EMAIL_REGEX,SHA_REGEX,SHA512_REGEX,MD5_REGEX,ATTACK_REGEX,URL_REGEX,CVE_REGEX ):    
                regex=re.compile(expr2)
                if regex.match(matchedtext):
                    content=content.replace(expr3.format(matchedtext), matchedtext)
    return content

'''
Check to to see if the friendly_id for report already exists
returns id of report if exists else none
Thinking will use some ajax on new reports/edit report so we don't get primary key error
'''
@app.route('/report/friendly_id_check/')
@login_required
def report_friendly_id_check(friendly_id=None):
    if friendly_id==None:
        if request.args.get('friendly_id'):
            friendly_id=request.args.get('friendly_id')
        elif request.form.get('friendly_id'):
            friendly_id=request.args.get('friendly_id')
    report=Reports.query.filter_by(friendly_id=friendly_id).first()
    if report:
        return jsonify({'id':report.id})
    else: 
        return jsonify({'id':'None'})