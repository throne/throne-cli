# LICENSED UNDER BSD-3-CLAUSE-CLEAR LICENSE
# SEE PROVIDED LICENSE FILE IN ROOT DIRECTORY

# Import Third Party Modules
import json
import urllib3
import sys
import logging
# Import Throne Modules
from src.exceptions import (ThroneParsingError, ThroneFormattingError, ThroneLookupFailed, ThroneHTTPError)

# Set log variable for verbose output
log = logging.getLogger(__name__)

class _APIInfo():
    def __init__(self, json_result):
        self.json = json_result
        self.vars = {
            'scan_credits': None,
            'scan_limit': None,
            'query_limit': None,
            'ip_limit': None,
            'plan': None,
            'unlocked': None,
            'query_credits': None,
            'monitored_ips': None,
            'unlocked_left': None,
            'used_scan_credits': None,
            'used_query_credits': None,
        }
    def parse(self):
        self.vars['scan_credits'] = self.json['scan_credits']
        self.vars['scan_limit'] = self.json['usage_limits']['scan_credits']
        self.vars['query_limit'] = self.json['usage_limits']['query_credits']
        self.vars['ip_limit'] = self.json['usage_limits']['monitored_ips']
        self.vars['plan'] = self.json['plan']
        self.vars['unlocked'] = self.json['unlocked']
        self.vars['query_credits'] = self.json['query_credits']
        self.vars['monitored_ips'] = self.json['monitored_ips']
        self.vars['unlocked_left'] = self.json['unlocked_left']
        
        self.vars['used_scan_credits'] = self.vars['scan_limit'] - self.vars['scan_credits']
        self.vars['used_query_credits'] = self.vars['query_limit'] - self.vars['query_credits']


class _DNS():
    def __init__(self, json_result, query_type):
        self.json = json_result
        self.type = query_type
        self.vars = {}
        self.reverse_vars = {
            'ip': None,
            'hostname': None,
        }
        self.resolve_vars = {
            'ip': None,
            'hostname': None,
        }
        self.record_vars = {
                'value': None,
                'subdomain': None,
                'type': None,
                'ports': None,
                'last_seen': None
            }
    def parse(self):
        if "reverse" in self.type:
            self.vars.update({
                'result': []
            })
            for k,v in self.json.items():
                self.resolve_vars = {
                'ip': None,
                'hostname': None,
                }
                self.resolve_vars['ip'] = k
                try:
                    for hostname in v:
                        self.resolve_vars['hostname'] = hostname
                except:
                    pass
                self.vars['result'].append(self.resolve_vars)
        if "resolve" in self.type:
            self.vars.update({
                'result': []
            })
            for k,v in self.json.items():
                self.resolve_vars = {
                'hostname': None,
                'ip': None,
                }
                self.resolve_vars['hostname'] = k
                self.resolve_vars['ip'] = v
                self.vars['result'].append(self.resolve_vars)
        if "domain" in self.type:
            self.vars.update({
            'domain': None,
            'tags': [],
            'subdomains': [],
            'records': [],
            })
            self.domain_vars = {}
            self.vars['domain'] = self.json['domain']
            if self.json['domain'] not in self.domain_vars.keys():
                domain = self.json['domain']
                self.domain_vars.update({domain: []})
            else:
                pass
            for tag in self.json['tags']:
                try:
                    self.vars['tags'].append(tag)
                except:
                    pass
            for subdomain in self.json['subdomains']:
                try:
                    subdomain = subdomain + f".{self.json['domain']}"
                    self.vars['subdomains'].append(subdomain)
                    if subdomain not in self.domain_vars.keys():
                        self.domain_vars.update({subdomain: []})
                    else:
                        pass
                except:
                    pass
            for record in self.json['data']:
                self.record_vars = {
                    'tags': [],
                    'value': None,
                    'domain': None,
                    'type': None,
                    'ports': [],
                    'last_seen': None,
                }
                for subdomain in self.domain_vars:
                    try:
                        try:
                            for tag in record['tags']:
                                if tag not in self.record_vars['tags']:
                                    self.record_vars['tags'].append(tag)
                        except:
                            pass
                        try:
                            self.record_vars['value'] = record['value']
                        except:
                            pass
                        try:
                            if record['subdomain'] == '':
                                self.record_vars['domain'] = self.json['domain']
                            else:
                                domain = record['subdomain'] + f".{self.json['domain']}"
                                self.record_vars['domain'] = domain
                        except:
                            pass
                        try:
                            self.record_vars['type'] = record['type']
                        except:
                            pass
                        try:
                            for port in record['ports']:
                                if port not in self.record_vars['ports']:
                                    self.record_vars['ports'].append(port)
                        except:
                            pass
                        try:
                            self.record_vars['last_seen'] = record['last_seen']
                        except:
                            pass
                        if subdomain == self.record_vars['domain']:
                            self.domain_vars[subdomain].append(self.record_vars)
                    except:
                        pass
                if self.domain_vars not in self.vars['records']:
                    self.vars['records'].append(self.domain_vars)
                else:
                    pass

class _IPSearch():
    def __init__(self, json_result, query):
        self.json = json_result
        self.query = query
        self.vars = {
            'query': self.query,
        }
    def parse(self):
        comma = ", "
        self.vars.update({
            'domains': [],
            'hostnames': [],
            'ports': [],
            'location': None,
            'coords': None,
            'protocols': [],
            'data': {}
        })
        for hostname in self.json['hostnames']:
            if hostname not in self.vars['hostnames']:
                self.vars['hostnames'].append(hostname)
        for domain in self.json['domains']:
            if domain not in self.vars['domains']:
                self.vars['domains'].append(domain)
        for port in self.json['ports']:
            if port not in self.vars['ports']:
                self.vars['ports'].append(port)
        result_location = [self.json['city'], self.json['region_code'], self.json['country_code']]
        result_location = comma.join(result_location)
        self.vars['location'] = result_location
        result_coords = [str(self.json['latitude']), str(self.json['longitude'])]
        result_coords = comma.join(result_coords)
        self.vars['coords'] = result_coords
        for data in self.json['data']:
            for k,v in data['_shodan'].items():
                if k == "module":
                    if v not in self.vars['protocols']:
                        self.vars['protocols'].append(v)
                    else:
                        v = v+"-1"
                    if "-1" not in v:
                        self.vars['data'].update({
                            v: [] 
                        })
                    else:
                        pass
            for protocol in self.vars['protocols']:
                self.protocol_vars = {
                    'ip': None,
                    'port': None,
                    'hostnames': [],
                    'domains': [],
                }
                if data['_shodan']['module'] == protocol:
                    self.protocol_vars['ip'] = data['ip_str']
                    self.protocol_vars['port'] = data['port']
                    for hostname in data['hostnames']:
                        if hostname not in self.protocol_vars['hostnames']:
                            self.protocol_vars['hostnames'].append(hostname)
                    for domain in data['domains']:
                        if domain not in self.protocol_vars['domains']:
                            self.protocol_vars['domains'].append(domain)
                    self.vars['data'][protocol].append(self.protocol_vars)