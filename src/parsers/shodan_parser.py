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