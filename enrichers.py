import whois
from flask import current_app
import requests
import re
import json
from datetime import datetime
from OTXv2 import OTXv2, IndicatorTypes
from shodan import Shodan
import traceback
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute

app= current_app

from lib import IP_REGEX, DOMAIN_REGEX,EMAIL_REGEX,SHA_REGEX,SHA512_REGEX,MD5_REGEX,ATTACK_REGEX, URL_REGEX, CVE_REGEX

def enrich_indicator(data):
    # Retrieve API Keys
    api_keys = {
        'otx_api_key': 'OTX_API_KEY',
        'shodan_api_key': 'SHODAN_API_KEY',
        'riskiq_username': 'RISKIQ_USERNAME',
        'riskiq_key': 'RISKIQ_KEY',
        'greynoise_api_key': 'GREYNOISE_API_KEY',
        'emailrep_api_key': 'EMAILREP_API_KEY',
        'vt_api_key': 'VT_API_KEY',
        'misp_api_key': 'MISP_API_KEY',
        'misp_url': 'MISP_URL',
        'hibp_api_key': 'HIBP_API_KEY',
        'hunter_api_key': 'HUNTER_API_KEY',
    }

    for key in api_keys:
        if not data.get(key):
            data[key] = app.config[api_keys[key]]

    # Detect indicator type
    indicator = data.get('indicator')
    types = {
        'ip': re.findall(IP_REGEX, indicator),
        'email_address': re.findall(EMAIL_REGEX, indicator),
        'url': re.findall(URL_REGEX, indicator),
        'domain': re.findall(DOMAIN_REGEX, indicator),
        'sha256': re.findall(SHA_REGEX, indicator),
        'md5': re.findall(MD5_REGEX, indicator),
        'sha512': re.findall(SHA512_REGEX, indicator),
        'attack': re.findall(ATTACK_REGEX, indicator),
        'cve': re.findall(CVE_REGEX, indicator),
    }

    indicator_type = next((key for key, value in types.items() if value), None)

    # Enrich based on indicator type
    update_data = {}

    if indicator_type == 'ip':
        update_data.update(get_ipinfo_data(indicator))
        update_data.update(get_otx_data(indicator, 'ip', data['otx_api_key']))
        update_data.update(get_shodan_data(indicator, data['shodan_api_key']))
        update_data.update(get_riskiq_data(indicator, data['riskiq_username'], data['riskiq_key']))
        update_data.update(get_greynoise_data(indicator, data['greynoise_api_key']))
        update_data.update(get_misp_data(indicator, 'ip-src', data['misp_api_key'], data['misp_url']))

    elif indicator_type == 'email_address':
        update_data.update(get_emailrep_data(indicator, data['emailrep_api_key']))
        update_data.update(get_misp_data(indicator, 'email-src', data['misp_api_key'], data['misp_url']))
        update_data.update(get_hibp_data(indicator, data['hibp_api_key']))
        update_data.update(get_hunter_data(indicator, data['hunter_api_key']))

    elif indicator_type == 'url':
        update_data.update(get_misp_data(indicator, 'url', data['misp_api_key'], data['misp_url']))
        # You mentioned get_urlscan_data for URL but didn't provide its structure
        update_data.update(get_urlscan_data(indicator))

    elif indicator_type == 'domain':
        update_data.update(get_otx_data(indicator, 'domain', data['otx_api_key']))
        update_data.update(get_riskiq_data(indicator, data['riskiq_username'], data['riskiq_key']))
        # You mentioned get_whois_data for domain but didn't provide its structure
        update_data.update(get_whois_data(indicator))
        update_data.update(get_misp_data(indicator, 'domain', data['misp_api_key'], data['misp_url']))

    elif indicator_type in ['sha256', 'md5', 'sha512']:
        update_data.update(get_vt_file_data(indicator, data['vt_api_key']))

        if indicator_type == 'md5':
            update_data.update(get_otx_data(indicator, 'md5', data['otx_api_key']))
            update_data.update(get_misp_data(indicator, 'md5', data['misp_api_key'], data['misp_url']))
        elif indicator_type == 'sha256':
            update_data.update(get_otx_data(indicator, 'sha256', data['otx_api_key']))
            update_data.update(get_misp_data(indicator, 'sha256', data['misp_api_key'], data['misp_url']))

    elif indicator_type == 'attack':
        # Placeholder for attack type
        update_data.update(get_attack_data(indicator))

    elif indicator_type == 'cve':
        # Placeholder for CVE type
        update_data.update(get_cve_data(indicator))
        update_data.update(get_misp_data(indicator, 'vulnerability', data['misp_api_key'], data['misp_url']))

    if update_data:
        update_data.update({'last_seen': datetime.now(), 'last_updated': datetime.now()})

    return update_data

def get_cve_data(indicator):
    base_url = 'http://cve.circl.lu/api/cve/'
    default_data = {
        'vuln_cvss': 'None',
        'vuln_references': 'None',
        'vuln_summary': 'None',
        'vuln_published': 'None',
        'vuln_modified': 'None'
    }

    try:
        response = requests.get(f'{base_url}{indicator}')
        response.raise_for_status()  # Raise an exception for HTTP errors

        vuln_data = response.json() or {}

        # Update default_data with actual values if available
        default_data.update({
            'vuln_cvss': vuln_data.get('cvss', 'None'),
            'vuln_references': ",".join(vuln_data.get('references', [])),
            'vuln_summary': vuln_data.get('summary', 'None'),
            'vuln_published': vuln_data.get('Published', 'None'),
            'vuln_modified': vuln_data.get('Modified', 'None')
        })

    except requests.RequestException:
        print(f'Failed to fetch data for CVE {indicator}')
    except Exception as err:
        print(f'cve-search error: {err}')

    return default_data

def get_vt_file_data(indicator, vt_api_key):
    default_data = {
        'vt_scan_date': 'None',
        'vt_positives': 'None'
    }

    if not vt_api_key:
        return default_data

    try:
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': vt_api_key, 'resource': indicator}
        response = requests.get(url, params=params)
        response.raise_for_status()  # Raise an exception for HTTP errors
        
        vt_data = response.json() or {}
        
        scan_date = vt_data.get('scan_date', 'None')
        positives = vt_data.get('positives', 0)
        total = vt_data.get('total', 0)

        default_data.update({
            'vt_scan_date': scan_date,
            'vt_positives': f'{positives}/{total}'
        })

    except requests.RequestException:
        print(f'Failed to fetch Virustotal data for indicator {indicator}')
    except Exception as err:
        print(f'Virustotal error for indicator {indicator}: {err}')

    return default_data

def get_hunter_data(indicator, hunter_api_key):
    default_data = {
        'hunter_result': 'None',
        'hunter_score': 'None',
        'hunter_disposable': 'None',
        'hunter_webmail': 'None',
        'hunter_mx_records': 'None',
        'hunter_smtp_server': 'None',
        'hunter_smtp_check': 'None',
        'hunter_blocked': 'None'
    }

    if not hunter_api_key:
        return default_data

    try:
        url = 'https://api.hunter.io/v2/email-verifier'
        params = {'api_key': hunter_api_key, 'email': indicator}
        
        response = requests.get(url, params=params)
        response.raise_for_status()  # Raise an exception for HTTP errors

        hunter_data = response.json().get('data', {})
        
        for key in default_data.keys():
            # Transforming 'hunter_result' to 'result'
            data_key = key.split('_', 1)[-1]
            default_data[key] = hunter_data.get(data_key, 'None')

    except requests.RequestException:
        print(f'Failed to fetch Hunter data for indicator {indicator}')
    except Exception as err:
        print(f'Hunter error for indicator {indicator}: {err}')

    return default_data

def get_attack_data(indicator):
    data = {
        'attack_permissionsrequired': 'n/a',
        'attack_name': 'n/a',
        'attack_description': 'n/a',
        'attack_platforms': 'n/a',
        'attack_detection': 'n/a'
    }

    try:
        r = requests.get('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json')
        r.raise_for_status()  # Raise an exception for HTTP errors

        attack_library = r.json()
        for thing in attack_library.get('objects', []):
            if thing.get('type') == 'attack-pattern':
                for source in thing.get('external_references', []):
                    if source.get('source_name') == 'mitre-attack' and source.get('external_id') == indicator:
                        data['attack_permissionsrequired'] = ', '.join(thing.get('x_mitre_permissions_required', ['n/a']))
                        data['attack_name'] = thing.get('name', 'n/a')
                        data['attack_description'] = thing.get('description', 'n/a')
                        data['attack_detection'] = thing.get('x_mitre_detection', 'n/a')
                        data['attack_platforms'] = ', '.join(thing.get('x_mitre_platforms', ['n/a']))
                        return data

    except requests.RequestException:
        print(f"Failed to fetch MITRE ATT&CK data for indicator {indicator}")
    except Exception as err:
        print(f"Error processing MITRE ATT&CK data for indicator {indicator}: {err}")

    return data

def get_vt_url_data(indicator, vt_api_key):
    data = {'vt_scan_date': 'n/a', 'vt_positives': 'n/a'}

    if not vt_api_key:
        return data

    try:
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': vt_api_key, 'resource': indicator}
        
        response = requests.get(url, params=params)
        response.raise_for_status()  # Raise an exception for HTTP errors

        json_data = response.json()
        scan_date = json_data.get('scan_date', 'n/a')
        positives = json_data.get('positives', 'n/a')
        total = json_data.get('total', 'n/a')

        data['vt_scan_date'] = scan_date
        data['vt_positives'] = f"{positives}/{total}"

    except requests.RequestException:
        print(f"Failed to fetch VirusTotal data for indicator {indicator}")
    except Exception as err:
        print(f"Error processing VirusTotal data for indicator {indicator}: {err}")

    return data

def get_whois_data(indicator):
    data = {
        'whois_creationdate': 'Unknown',
        'whois_registrar': 'Unknown',
        'whois_expirationdate': 'Unknown',
        'whois_nameservers': 'Unknown',
        'whois_lastupdated': 'Unknown'
    }
    
    def safe_date_format(date_obj):
        try:
            return date_obj.strftime("%m/%d/%Y")
        except AttributeError:
            return "Unknown"

    try:
        domain_details = whois.query(indicator)
        result = domain_details.__dict__

        data['whois_creationdate'] = safe_date_format(result.get('creation_date'))
        data['whois_expirationdate'] = safe_date_format(result.get('expiration_date'))
        data['whois_lastupdated'] = safe_date_format(result.get('last_updated'))
        data['whois_nameservers'] = ', '.join(result.get('name_servers', []))

    except Exception as err:
        print(f'Whois error on indicator {indicator} : {err}')

    return data

def get_urlscan_data(indicator):
    data = {
        'urlscan_score': 'n/a',
        'urlscan_categories': 'n/a',
        'urlscan_tags': 'n/a',
        'urlscan_malicious': 'n/a'
    }
    
    try:
        domain = re.search(r'https?://([A-Za-z_0-9.-]+).*', indicator)
        if domain:
            domain = domain.group(1)
            urlscan_result = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}")
            urlscan_result = urlscan_result.json()

            if urlscan_result.get('results'):
                latest_scan = urlscan_result['results'][0].get('result')
                if latest_scan:
                    latest_results = requests.get(latest_scan).json()
                    verdicts = latest_results.get('verdicts', {}).get('overall', {})

                    data['urlscan_score'] = str(verdicts.get('score', 'n/a'))
                    data['urlscan_categories'] = ', '.join(verdicts.get('categories', []))
                    data['urlscan_tags'] = ', '.join(verdicts.get('tags', []))
                    data['urlscan_malicious'] = str(verdicts.get('malicious', 'n/a'))

    except Exception as err:
        print(f'Urlscan error: {"".join(traceback.format_exception(type(err), err, err.__traceback__))}')

    return data

def get_emailrep_data(indicator, emailrep_api_key):
    data = {
        'emailrep_reputation': 'n/a',
        'emailrep_suspicious': 'n/a',
        'emailrep_references': 'n/a',
        'emailrep_blacklisted': 'n/a',
        'emailrep_maliciousactivity': 'n/a',
        'emailrep_credsleaked': 'n/a',
        'emailrep_databreach': 'n/a',
        'emailrep_first_seen': 'n/a',
        'emailrep_last_seen': 'n/a',
        'emailrep_domain_rep': 'n/a',
        'emailrep_profiles': 'n/a'
    }

    if emailrep_api_key:
        try:
            headers = {'key': emailrep_api_key}
            response = requests.get(f'https://emailrep.io/{indicator}', headers=headers)
            emailrep = response.json()

            details = emailrep.get('details', {})
            
            data['emailrep_reputation'] = emailrep.get('reputation', 'n/a')
            data['emailrep_suspicious'] = emailrep.get('suspicious', 'n/a')
            data['emailrep_references'] = emailrep.get('references', 'n/a')
            data['emailrep_blacklisted'] = details.get('blacklisted', 'n/a')
            data['emailrep_maliciousactivity'] = details.get('malicious_activity', 'n/a')
            data['emailrep_credsleaked'] = details.get('credentials_leaked', 'n/a')
            data['emailrep_databreach'] = details.get('data_breach', 'n/a')
            data['emailrep_first_seen'] = details.get('first_seen', 'n/a')
            data['emailrep_last_seen'] = details.get('last_seen', 'n/a')
            data['emailrep_domain_rep'] = details.get('domain_reputation', 'n/a')
            data['emailrep_profiles'] = ', '.join(details.get('profiles', []))

        except Exception as err:
            print(f'Emailrep error: {"".join(traceback.format_exception(type(err), err, err.__traceback__))}')

    return data

def get_hibp_data(indicator, hibp_api_key):
    data = {'hibp_breaches': 'n/a'}

    if not hibp_api_key:
        return data

    url = 'https://haveibeenpwned.com/api/v3/breachedaccount/' + indicator
    headers = {'hibp-api-key': hibp_api_key}

    try:
        response = requests.get(url, headers=headers)

        # Check if the response is successful
        response.raise_for_status()

        # Fetch the breaches from the response
        breaches = [breach.get('Name') for breach in response.json()]
        data['hibp_breaches'] = ", ".join(breaches)

    except requests.RequestException as err:
        print(f"Have I Been Pwned API error: {err}")
    
    return data

def get_riskiq_data(indicator, riskiq_username, riskiq_key):
    data = {
        'risk_classifications': 'n/a',
        'risk_sinkhole': 'n/a',
        'risk_evercompromised': 'n/a',
        'risk_primarydomain': 'n/a',
        'risk_tags': 'n/a',
        'risk_dynamicdns': 'n/a',
        'risk_sources': 'n/a'
    }

    if not all([indicator, riskiq_username, riskiq_key]):
        return data

    auth = (riskiq_username, riskiq_key)
    headers = {"Accept": "application/json"}
    params = {"query": indicator}

    try:
        response = requests.get('https://api.riskiq.net/pt/v2/enrichment', params=params, auth=auth, headers=headers)
        response.raise_for_status()
        risk_data = response.json()

        data['risk_classifications'] = risk_data.get('classification', 'n/a')
        data['risk_sinkhole'] = risk_data.get('sinkhole', 'n/a')
        data['risk_evercompromised'] = risk_data.get('everCompromised', 'n/a')
        data['risk_primarydomain'] = risk_data.get('primaryDomain', 'n/a')
        data['risk_dynamicdns'] = risk_data.get('dynamicDns', 'n/a')

        tags = risk_data.get('tags', [])
        
        response = requests.get('https://api.riskiq.net/pt/v2/enrichment/osint', params=params, auth=auth, headers=headers)
        response.raise_for_status()
        osint_data = response.json()

        sources = [source['sourceUrl'] for source in osint_data.get('results', []) if source['sourceUrl'] not in tags]
        tags.extend(source.get('tags', []))

        data['risk_tags'] = ", ".join(set(tags))
        data['risk_sources'] = ", ".join(sources)

    except requests.RequestException as err:
        print(f'RiskIQ error for indicator {indicator}: {err}')

    return data

def get_otx_data(indicator, ind_type, otx_api_key):
    data = {
        'av_general': 'n/a',
        'av_reputation': 'n/a',
        'av_malware_data': 'n/a',
        'av_url_data': 'n/a',
        'av_passive_data': 'n/a',
        'av_pulse_count': '0',
        'av_tlp': 'n/a'
    }

    if not otx_api_key:
        return data

    try:
        otx = OTXv2(otx_api_key)
        
        indicator_func_map = {
            'md5': IndicatorTypes.FILE_HASH_MD5,
            'sha256': IndicatorTypes.FILE_HASH_SHA256,
            'domain': IndicatorTypes.DOMAIN,
            'ip': IndicatorTypes.IPv4
        }
        
        if ind_type in indicator_func_map:
            indicator_details = otx.get_indicator_details_full(indicator_func_map[ind_type], indicator)
            
            if indicator_details:
                general_info = indicator_details.get('general', {})
                data.update({
                    'av_general': str(general_info),
                    'av_reputation': str(indicator_details.get('reputation', {}).get('reputation')),
                    'av_malware_data': str(indicator_details.get('malware', {}).get('data')),
                    'av_url_data': str(indicator_details.get('url_list', {}).get('url_list')),
                    'av_passive_data': str(indicator_details.get('passive_dns')),
                    'av_pulse_count': str(general_info.get('pulse_info', {}).get('count')),
                    'av_tlp': str(indicator_details.get('analysis', {}).get('analysis', {}).get('metadata', {}).get('tlp'))
                })
    except Exception as err:
        print(f'OTX error for indicator {indicator}: {"".join(traceback.format_exception(type(err), err, err.__traceback__))}')
        
    return data
    
def get_shodan_data(indicator, shodan_api_key):
    data = {
        'shodan_tags': 'None',
        'shodan_region': 'None',
        'shodan_postal': 'None',
        'shodan_country': 'None',
        'shodan_city': 'None',
        'shodan_ports': 'None',
        'shodan_hostnames': 'None',
        'shodan_org': 'None'
    }

    if not shodan_api_key:
        return data

    try:
        shodan_api = Shodan(shodan_api_key)
        shodan_query = shodan_api.host(indicator)

        # Extract tags
        tags = shodan_query.get('tags', [])
        if tags:
            data['shodan_tags'] = ", ".join(tags)

        # Extract region, postal, country, and city info
        for key, prefix in zip(['region_code', 'postal_code', 'country_code', 'city'], 
                               ['shodan_region', 'shodan_postal', 'shodan_country', 'shodan_city']):
            data[prefix] = shodan_query.get(key, 'None')
        
        # Extract port data
        ports = [str(item['port']) for item in shodan_query.get('data', [])]
        if ports:
            data['shodan_ports'] = ", ".join(ports)
        
        # Extract hostnames and organization
        data['shodan_hostnames'] = str(shodan_query.get('hostnames', 'None'))
        data['shodan_org'] = shodan_query.get('org', 'None')
        
    except Exception as err:
        print(f'Shodan error for indicator {indicator}: {"".join(traceback.format_exception(type(err), err, err.__traceback__))}')
        
    return data

def get_ipinfo_data(indicator):
    try:
        response = requests.get(f'https://ipinfo.io/{indicator}')
        response.raise_for_status()  # Raise an error for bad responses
        
        ipinfo = response.json()
        
        return {
            'ipinfo_city': ipinfo.get('city', 'Unknown'),
            'ipinfo_hostname': ipinfo.get('hostname', 'Unknown'),
            'ipinfo_region': ipinfo.get('region', 'Unknown'),
            'ipinfo_country': ipinfo.get('country', 'Unknown'),
            'ipinfo_org': ipinfo.get('org', 'Unknown'),
            'ipinfo_postal': ipinfo.get('postal', 'Unknown')
        }
    except Exception as err:
        print(f'IpInfo error for indicator {indicator}: {"".join(traceback.format_exception(type(err), err, err.__traceback__))}')
        return {}

def get_greynoise_data(indicator, greynoise_api_key):
    data = {
        'gn_seen': 'Unknown',
        'gn_classification': 'Unknown',
        'gn_first_seen': 'Unknown',
        'gn_last_seen': 'Unknown',
        'gn_actor': 'Unknown',
        'gn_tags': 'Unknown'
    }

    if greynoise_api_key:
        try:
            headers = {
                'Accept': 'application/json',
                'key': greynoise_api_key
            }

            response = requests.get(f'https://api.greynoise.io/v2/noise/context/{indicator}', headers=headers)
            response.raise_for_status()

            gn_data = response.json()
            data.update({
                'gn_seen': gn_data.get('seen', 'Unknown'),
                'gn_classification': gn_data.get('classification', 'Unknown'),
                'gn_first_seen': gn_data.get('first_seen', 'Unknown'),
                'gn_last_seen': gn_data.get('last_seen', 'Unknown'),
                'gn_actor': gn_data.get('actor', 'Unknown'),
                'gn_tags': ', '.join(gn_data.get('tags', []))
            })

        except Exception as err:
            print(f'Greynoise error for indicator {indicator}: {"".join(traceback.format_exception(type(err), err, err.__traceback__))}')

    return data

def get_misp_data(indicator, indicator_type, misp_api_key, misp_url):
    default_data = {
        'misp_eventid': 'n/a',
        'misp_firstseen': 'n/a',
        'misp_lastseen': 'n/a',
        'misp_eventinfo': 'n/a',
        'misp_dateadded': 'n/a',
        'misp_comment': 'n/a'
    }

    if not misp_api_key:
        return default_data

    try:
        misp = ExpandedPyMISP(misp_url, misp_api_key, True)
        body = {
            "returnFormat": "json",
            "type": indicator_type,
            "value": indicator
        }
        misp_query = misp.direct_call('attributes/restSearch', body)

        if 'Attribute' not in misp_query or not misp_query['Attribute']:
            return default_data

        attribute_data = misp_query['Attribute'][0]
        
        ts = attribute_data.get('timestamp')
        date_added = datetime.fromtimestamp(int(ts)).isoformat() if ts and ts.isdigit() else ts

        return {
            'misp_eventid': attribute_data.get('event_id', 'n/a'),
            'misp_firstseen': attribute_data.get('first_seen', 'n/a'),
            'misp_lastseen': attribute_data.get('last_seen', 'n/a'),
            'misp_eventinfo': attribute_data.get('Event', {}).get('info', 'n/a'),
            'misp_dateadded': date_added,
            'misp_comment': attribute_data.get('Event', {}).get('comment', 'n/a')
        }
    
    except Exception as err:
        print(f'MISP error for indicator {indicator}: {"".join(traceback.format_exception(type(err), err, err.__traceback__))}')
    
    return default_data

def export_to_misp(user_details, report, indicators):
    # Extract user details
    misp_url = user_details.get('misp_url')
    misp_key = user_details.get('misp_api_key')
    
    # Create MISP instance
    misp = ExpandedPyMISP(misp_url, misp_key, True)

    # Create and add MISP event
    event = MISPEvent()
    event.info = report.title
    event = misp.add_event(event, pythonify=True)
    created = json.loads(event.to_json())
    event_id = created.get('id')
    
    # Mapping indicator types to MISP types
    indicator_type_mapping = {
        'IP': 'ip-dst',
        'Domain': 'domain',
        'Email': 'email-src',
        'CVE': 'vulnerability',
        'MD5 Hash': 'md5',
        'SHA256 Hash': 'sha256',
        'URL': 'url'
    }

    for _, indicator_value, indicator_key in indicators:
        indicator_type = indicator_type_mapping.get(indicator_key)

        if not indicator_type:
            continue

        if indicator_key == 'CVE':
            indicator_value = indicator_value.replace('_', '-')
        
        try:
            misp.add_attribute(event_id, {'type': indicator_type, 'value': indicator_value}, pythonify=True)
        except Exception as e:
            print(f"Failed to add attribute: {indicator_value}. Error: {e}")