from flask_login import UserMixin
from config import db

class Organization(db.Model): 
    id = db.Column(db.Integer, primary_key=True) 
    name = db.Column(db.String(200), unique=True) 
    org_key =db.Column(db.String(100), unique=True)# some key for new users to register wth
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now()) 
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now()) 
    whois_enabled = db.Column(db.Boolean, default=True)
    ipinfo_enabled = db.Column(db.Boolean, default=True)
    vt_enabled = db.Column(db.Boolean, default=False)
    vt_api_key = db.Column(db.String(1000))
    shodan_enabled = db.Column(db.Boolean, default=False)
    shodan_api_key = db.Column(db.String(1000))
    urlscan_enabled = db.Column(db.Boolean, default=False)
    urlscan_api_key = db.Column(db.String(1000))
    emailrep_enabled = db.Column(db.Boolean, default=False)
    emailrep_api_key = db.Column(db.String(1000))
    riskiq_enabled = db.Column(db.Boolean, default=False)
    riskiq_username = db.Column(db.String(50))
    riskiq_api_key = db.Column(db.String(50))
    gn_enabled = db.Column(db.Boolean, default=False)
    gn_api_key = db.Column(db.String(50))
    av_enabled = db.Column(db.Boolean, default=False)
    av_api_key = db.Column(db.String(100))
    misp_enabled = db.Column(db.Boolean, default=False)
    misp_api_key = db.Column(db.String(100))
    misp_url = db.Column(db.String(1000))
    hibp_api_key = db.Column(db.String(100))
    hibp_enabled = db.Column(db.Boolean, default=False)
    hunter_api_key = db.Column(db.String(100))
    hunter_enabled = db.Column(db.Boolean, default=False)
    slack_webhook = db.Column(db.String(1000))
    slack_webhook_on_report_create = db.Column(db.Boolean, default=False)
    slack_webhook_on_req_create = db.Column(db.Boolean, default=False)
    slack_webhook_on_req_update = db.Column(db.Boolean, default=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    organization = db.Column(db.Integer, db.ForeignKey('organization.id'))# add foreign key 
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    tn_api_key = db.Column(db.String(50))
    role = db.Column(db.String(50), default='user')
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now()) 
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())  
    new_user = db.Column(db.Boolean, default=True)


class Indicators(db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    indicator = db.Column(db.String(500), unique=True)
    date_created = db.Column(db.DateTime(timezone=True), server_default=db.func.now()) 
    last_seen = db.Column(db.DateTime(timezone=True), server_default=db.func.now()) 
    last_updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now()) 
    indicator_type = db.Column(db.String(1000))
    #diamond_model = db.Column(db.String(1000))
    #kill_chain = db.Column(db.String(1000))
    #confidence = db.Column(db.String(1000))
    
    # ipinfo.io Enrichment
    ipinfo_hostname = db.Column(db.String(100))
    ipinfo_city = db.Column(db.String(1000))
    ipinfo_region = db.Column(db.String(1000))
    ipinfo_postal = db.Column(db.String(1000))
    ipinfo_country = db.Column(db.String(1000))
    ipinfo_org = db.Column(db.String(1000))

    # ATT&CK Enrichment
    attack_name = db.Column(db.String(1000))
    attack_permissionsrequired = db.Column(db.String(1000))
    attack_description = db.Column(db.String(1000))
    attack_platforms = db.Column(db.String(1000))
    attack_detection = db.Column(db.String(1000))
    attack_killchain = db.Column(db.String(1000))

    # Domain WHOIS Enrichment
    whois_registrar = db.Column(db.String(1000))
    whois_creationdate = db.Column(db.String(1000))
    whois_expirationdate = db.Column(db.String(1000))
    whois_lastupdated = db.Column(db.String(1000))
    whois_nameservers = db.Column(db.String(1000))

    # VirusTotal Enrichment
    vt_scan_date = db.Column(db.String(1000))
    vt_positives = db.Column(db.String(1000))

    # Emailrep Enrichment
    emailrep_reputation= db.Column(db.String(1000))
    emailrep_suspicious = db.Column(db.String(1000))
    emailrep_references = db.Column(db.String(1000))
    emailrep_blacklisted= db.Column(db.String(1000))
    emailrep_maliciousactivity = db.Column(db.String(1000))
    emailrep_credsleaked = db.Column(db.String(1000))
    emailrep_databreach = db.Column(db.String(1000))
    emailrep_first_seen = db.Column(db.String(1000))
    emailrep_last_seen = db.Column(db.String(1000))
    emailrep_domain_rep = db.Column(db.String(1000))
    emailrep_profiles = db.Column(db.String(1000))

    # AlienVault OTX Enrichment
    av_reputation = db.Column(db.String(1000))
    av_malware_data = db.Column(db.String(100000))
    av_url_data = db.Column(db.String(100000))
    av_passive_data = db.Column(db.String(100000))
    av_general = db.Column(db.String(1000000))
    av_pulse_count = db.Column(db.String(1000000))
    av_tlp = db.Column(db.String(1000000))

    # Shodan Enrichment
    shodan_tags = db.Column(db.String(100000))
    shodan_region = db.Column(db.String(100000))
    shodan_postal = db.Column(db.String(100000))
    shodan_country = db.Column(db.String(100000))
    shodan_city = db.Column(db.String(100000))
    shodan_ports = db.Column(db.String(100000))
    shodan_hostnames = db.Column(db.String(100000))
    shodan_org = db.Column(db.String(100000))

    # Urlscan.io
    urlscan_categories = db.Column(db.String(100000))
    urlscan_tags = db.Column(db.String(100000))
    urlscan_score = db.Column(db.String(100000))
    urlscan_malicious = db.Column(db.String(100000))

    # RiskIQ
    risk_classifications=db.Column(db.String(100000))
    risk_sinkhole = db.Column(db.String(100000))
    risk_evercompromised = db.Column(db.String(100000))
    risk_primarydomain = db.Column(db.String(100000))
    risk_subdomains = db.Column(db.String(100000))
    risk_tags = db.Column(db.String(100000))
    risk_dynamicdns = db.Column(db.String(100000))
    risk_sources = db.Column(db.String(100000))

    # Greynoise
    gn_seen = db.Column(db.String(100000))
    gn_classification = db.Column(db.String(100000))
    gn_first_seen = db.Column(db.String(100000))
    gn_last_seen = db.Column(db.String(100000))
    gn_actor = db.Column(db.String(100000))
    gn_tags = db.Column(db.String(100000))

    # CIRCL CVE-SEARCH
    vuln_cvss = db.Column(db.String(100000))
    vuln_references = db.Column(db.String(100000))
    vuln_summary = db.Column(db.String(100000))
    vuln_published = db.Column(db.String(100000))
    vuln_modified = db.Column(db.String(100000))

    # MISP
    misp_eventid = db.Column(db.String(100000))
    misp_firstseen = db.Column(db.String(100000))
    misp_lastseen = db.Column(db.String(100000))
    misp_eventinfo = db.Column(db.String(100000))
    misp_dateadded = db.Column(db.String(100000))
    misp_comment = db.Column(db.String(100000))

    #HIBP
    hibp_breaches = db.Column(db.String(100000))

    #Hunter
    hunter_result = db.Column(db.String(100000))
    hunter_score = db.Column(db.String(100000))
    hunter_disposable = db.Column(db.String(100000))
    hunter_webmail = db.Column(db.String(100000))
    hunter_mx_records = db.Column(db.String(100000))
    hunter_smtp_server = db.Column(db.String(100000))
    hunter_smtp_check = db.Column(db.String(100000))
    hunter_blocked = db.Column(db.String(100000))

    def as_dict(self):
        return {
            'id': self.id,
            'indicator': self.indicator,
            'date_created': self.date_created,
            'last_seen': self.last_seen,
            'last_updated': self.last_updated,
            'indicator_type': self.indicator_type,
            
            # ipinfo.io Enrichment
            'ipinfo_hostname': self.ipinfo_hostname,
            'ipinfo_city': self.ipinfo_city,
            'ipinfo_region': self.ipinfo_region,
            'ipinfo_postal': self.ipinfo_postal,
            'ipinfo_country': self.ipinfo_country,
            'ipinfo_org': self.ipinfo_org,

            # ATT&CK Enrichment
            'attack_name': self.attack_name,
            'attack_permissionsrequired': self.attack_permissionsrequired,
            'attack_description': self.attack_description,
            'attack_platforms': self.attack_platforms,
            'attack_detection': self.attack_detection,
            'attack_killchain': self.attack_killchain,

            # Domain WHOIS Enrichment
            'whois_registrar': self.whois_registrar,
            'whois_creationdate': self.whois_creationdate,
            'whois_expirationdate': self.whois_expirationdate,
            'whois_lastupdated': self.whois_lastupdated,
            'whois_nameservers': self.whois_nameservers,

            # VirusTotal Enrichment
            'vt_scan_date': self.vt_scan_date,
            'vt_positives': self.vt_positives,

            # Emailrep Enrichment
            'emailrep_reputation': self.emailrep_reputation,
            'emailrep_suspicious': self.emailrep_suspicious,
            'emailrep_references': self.emailrep_references,
            'emailrep_blacklisted': self.emailrep_blacklisted,
            'emailrep_maliciousactivity': self.emailrep_maliciousactivity,
            'emailrep_credsleaked': self.emailrep_credsleaked,
            'emailrep_databreach': self.emailrep_databreach,
            'emailrep_first_seen': self.emailrep_first_seen,
            'emailrep_last_seen': self.emailrep_last_seen,
            'emailrep_domain_rep': self.emailrep_domain_rep,
            'emailrep_profiles': self.emailrep_profiles,

            # AlienVault OTX Enrichment
            'av_reputation': self.av_reputation,
            'av_malware_data': self.av_malware_data,
            'av_url_data': self.av_url_data,
            'av_passive_data': self.av_passive_data,
            'av_general': self.av_general,
            'av_pulse_count': self.av_pulse_count,
            'av_tlp': self.av_tlp,

            # Shodan Enrichment
            'shodan_tags': self.shodan_tags,
            'shodan_region': self.shodan_region,
            'shodan_postal': self.shodan_postal,
            'shodan_country': self.shodan_country,
            'shodan_city': self.shodan_city,
            'shodan_ports': self.shodan_ports,
            'shodan_hostnames': self.shodan_hostnames,
            'shodan_org': self.shodan_org,

            # Urlscan.io
            'urlscan_categories': self.urlscan_categories,
            'urlscan_tags': self.urlscan_tags,
            'urlscan_score': self.urlscan_score,
            'urlscan_malicious': self.urlscan_malicious,

            # RiskIQ
            'risk_classifications': self.risk_classifications,
            'risk_sinkhole': self.risk_sinkhole,
            'risk_evercompromised': self.risk_evercompromised,
            'risk_primarydomain': self.risk_primarydomain,
            'risk_subdomains': self.risk_subdomains,
            'risk_tags': self.risk_tags,
            'risk_dynamicdns': self.risk_dynamicdns,
            'risk_sources': self.risk_sources,

            # Greynoise
            'gn_seen': self.gn_seen,
            'gn_classification': self.gn_classification,
            'gn_first_seen': self.gn_first_seen,
            'gn_last_seen': self.gn_last_seen,
            'gn_actor': self.gn_actor,
            'gn_tags': self.gn_tags,

            # CIRCL CVE-SEARCH
            'vuln_cvss': self.vuln_cvss,
            'vuln_references': self.vuln_references,
            'vuln_summary': self.vuln_summary,
            'vuln_published': self.vuln_published,
            'vuln_modified': self.vuln_modified,

            # MISP
            'misp_eventid': self.misp_eventid,
            'misp_firstseen': self.misp_firstseen,
            'misp_lastseen': self.misp_lastseen,
            'misp_eventinfo': self.misp_eventinfo,
            'misp_dateadded': self.misp_dateadded,
            'misp_comment': self.misp_comment,

            # HIBP
            'hibp_breaches': self.hibp_breaches,

            # Hunter
            'hunter_result': self.hunter_result,
            'hunter_score': self.hunter_score,
            'hunter_disposable': self.hunter_disposable,
            'hunter_webmail': self.hunter_webmail,
            'hunter_mx_records': self.hunter_mx_records,
            'hunter_smtp_server': self.hunter_smtp_server,
            'hunter_smtp_check': self.hunter_smtp_check,
            'hunter_blocked': self.hunter_blocked,
        }


class Requirements(db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    friendly_id = db.Column(db.String(100), unique=True)
    title = db.Column(db.String(500))
    owner = db.Column(db.String(100))
    priority = db.Column(db.String(100))
    summary = db.Column(db.String(10000))
    gaps = db.Column(db.String(10000))
    collection_requirements = db.Column(db.String(10000))
    deliverables = db.Column(db.String(10000))
    time_requirement = db.Column(db.Date())
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now()) 
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now()) 
    creator = db.Column(db.String(100))
    is_archived = db.Column(db.Boolean, default=False)
#    consumers = db.Column(db.String(1000))

class Reports(db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    title = db.Column(db.String(500))
    content = db.Column(db.String(100000))
    creator = db.Column(db.String(100))   
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now()) 
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now()) 
    friendly_id = db.Column(db.String(100))
    is_archived = db.Column(db.Boolean, default=False)
    #tags = db.Column(db.String(1000))
#    linked_reqs = db.Column(db.String(1000))
    tlp = db.Column(db.String(100))
#    consumers = db.Column(db.String(10000))

class ReportTags(db.Model):
    report = db.Column(db.Integer, db.ForeignKey('reports.id'), primary_key=True)
    tag = db.Column(db.String(100), nullable=False, primary_key=True)
       
class Links(db.Model):
#    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    indicator = db.Column(db.Integer, db.ForeignKey('indicators.id'), primary_key=True)# add foreign key 
    report = db.Column(db.Integer, db.ForeignKey('reports.id'), primary_key=True)# add foreign key 
    diamond_model = db.Column(db.String(1000))
    kill_chain = db.Column(db.String(1000))
    confidence = db.Column(db.String(1000))
    
class Consumers(db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    organization = db.Column(db.Integer, db.ForeignKey('organization.id'))# add foreign key 
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    poc = db.Column(db.String(100))
    subtitle = db.Column(db.String(100))
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now()) 
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now()) 

class RequirementConsumers(db.Model):
    consumer = db.Column(db.Integer, db.ForeignKey('consumers.id'), primary_key=True)
    requirement = db.Column(db.Integer, db.ForeignKey('requirements.id'), primary_key=True)

class RequirementReports(db.Model):
    requirement = db.Column(db.Integer, db.ForeignKey('requirements.id'), primary_key=True)
    report = db.Column(db.Integer, db.ForeignKey('reports.id'), primary_key=True)

class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    user = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report = db.Column(db.Integer, db.ForeignKey('reports.id'), nullable=True)
    requirement = db.Column(db.Integer, db.ForeignKey('reports.id'), nullable=True)
    comment = db.Column(db.String(100000), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now()) 
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now()) 
    indicator = db.Column(db.Integer, db.ForeignKey('indicators.id'), nullable=True)
