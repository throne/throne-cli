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

class _LGParse():
    def __init__(self, json_result):
        self.json = json_result
        self.vars = {
            'cached': None,
            'data': {},
            'query_info': {}
        }
    
    def parse(self):
        self.vars['cached'] = self.json['cached']
        self.vars['query_info'].update({
            'status': None,
            'time': None,
            'query_time': None,
            'data_last_update': None
        })
        self.vars['query_info']['status'] = self.json['status']
        self.vars['query_info']['time'] = self.json['time']
        self.vars['query_info']['query_time'] = self.json['data']['query_time']
        self.vars['query_info']['latest_poll'] = self.json['data']['latest_time']

        self.vars['data'].update({
            'US-NY': {},
            'US-FL': {},
            'US-CA': {},
            'UK': {},
            'NL': {},
            'SG': {},
            'DE': {},
            'ZA': {},
            'JP': {}
        })
        
        for entries in self.json['data']['rrcs']:
            location = entries['location']
            origin_as = entries['peers'][0]['asn_origin']
            as_path = entries['peers'][0]['as_path']
            communities = entries['peers'][0]['community']
            last_updated = entries['peers'][0]['last_updated']
            prefix = entries['peers'][0]['prefix']
            peer = entries['peers'][0]['peer']
            origin = entries['peers'][0]['origin']
            next_hop = entries['peers'][0]['next_hop']
            latest_poll = entries['peers'][0]['latest_time']
            if "New York" in entries['location']:
                self.vars['data']['US-NY']['location'] = location
                self.vars['data']['US-NY']['origin_as'] = origin_as
                self.vars['data']['US-NY']['as_path'] = as_path
                self.vars['data']['US-NY']['communities'] = communities
                self.vars['data']['US-NY']['last_updated'] = last_updated
                self.vars['data']['US-NY']['prefix'] = prefix
                self.vars['data']['US-NY']['peer'] = peer
                self.vars['data']['US-NY']['origin'] = origin
                self.vars['data']['US-NY']['next_hop'] = next_hop
                self.vars['data']['US-NY']['latest_poll'] = latest_poll
            if "Florida" in entries['location']:
                self.vars['data']['US-FL']['location'] = location
                self.vars['data']['US-FL']['origin_as'] = origin_as
                self.vars['data']['US-FL']['as_path'] = as_path
                self.vars['data']['US-FL']['communities'] = communities
                self.vars['data']['US-FL']['last_updated'] = last_updated
                self.vars['data']['US-FL']['prefix'] = prefix
                self.vars['data']['US-FL']['peer'] = peer
                self.vars['data']['US-FL']['origin'] = origin
                self.vars['data']['US-FL']['next_hop'] = next_hop
                self.vars['data']['US-FL']['latest_poll'] = latest_poll
            if "California" in entries['location']:
                self.vars['data']['US-CA']['location'] = location
                self.vars['data']['US-CA']['origin_as'] = origin_as
                self.vars['data']['US-CA']['as_path'] = as_path
                self.vars['data']['US-CA']['communities'] = communities
                self.vars['data']['US-CA']['last_updated'] = last_updated
                self.vars['data']['US-CA']['prefix'] = prefix
                self.vars['data']['US-CA']['peer'] = peer
                self.vars['data']['US-CA']['origin'] = origin
                self.vars['data']['US-CA']['next_hop'] = next_hop
                self.vars['data']['US-CA']['latest_poll'] = latest_poll
            if "United Kingdom" in entries['location']:
                self.vars['data']['UK']['location'] = location
                self.vars['data']['UK']['origin_as'] = origin_as
                self.vars['data']['UK']['as_path'] = as_path
                self.vars['data']['UK']['communities'] = communities
                self.vars['data']['UK']['last_updated'] = last_updated
                self.vars['data']['UK']['prefix'] = prefix
                self.vars['data']['UK']['peer'] = peer
                self.vars['data']['UK']['origin'] = origin
                self.vars['data']['UK']['next_hop'] = next_hop
                self.vars['data']['UK']['latest_poll'] = latest_poll
            if "Netherlands" in entries['location']:
                self.vars['data']['NL']['location'] = location
                self.vars['data']['NL']['origin_as'] = origin_as
                self.vars['data']['NL']['as_path'] = as_path
                self.vars['data']['NL']['communities'] = communities
                self.vars['data']['NL']['last_updated'] = last_updated
                self.vars['data']['NL']['prefix'] = prefix
                self.vars['data']['NL']['peer'] = peer
                self.vars['data']['NL']['origin'] = origin
                self.vars['data']['NL']['next_hop'] = next_hop
                self.vars['data']['NL']['latest_poll'] = latest_poll
            if "Singapore" in entries['location']:
                self.vars['data']['SG']['location'] = location
                self.vars['data']['SG']['origin_as'] = origin_as
                self.vars['data']['SG']['as_path'] = as_path
                self.vars['data']['SG']['communities'] = communities
                self.vars['data']['SG']['last_updated'] = last_updated
                self.vars['data']['SG']['prefix'] = prefix
                self.vars['data']['SG']['peer'] = peer
                self.vars['data']['SG']['origin'] = origin
                self.vars['data']['SG']['next_hop'] = next_hop
                self.vars['data']['SG']['latest_poll'] = latest_poll
            if "Germany" in entries['location']:
                self.vars['data']['DE']['location'] = location
                self.vars['data']['DE']['origin_as'] = origin_as
                self.vars['data']['DE']['as_path'] = as_path
                self.vars['data']['DE']['communities'] = communities
                self.vars['data']['DE']['last_updated'] = last_updated
                self.vars['data']['DE']['prefix'] = prefix
                self.vars['data']['DE']['peer'] = peer
                self.vars['data']['DE']['origin'] = origin
                self.vars['data']['DE']['next_hop'] = next_hop
                self.vars['data']['DE']['latest_poll'] = latest_poll
            if "South Africa" in entries['location']:
                self.vars['data']['ZA']['location'] = location
                self.vars['data']['ZA']['origin_as'] = origin_as
                self.vars['data']['ZA']['as_path'] = as_path
                self.vars['data']['ZA']['communities'] = communities
                self.vars['data']['ZA']['last_updated'] = last_updated
                self.vars['data']['ZA']['prefix'] = prefix
                self.vars['data']['ZA']['peer'] = peer
                self.vars['data']['ZA']['origin'] = origin
                self.vars['data']['ZA']['next_hop'] = next_hop
                self.vars['data']['ZA']['latest_poll'] = latest_poll
            if "Japan" in entries['location']:
                self.vars['data']['JP']['location'] = location
                self.vars['data']['JP']['origin_as'] = origin_as
                self.vars['data']['JP']['as_path'] = as_path
                self.vars['data']['JP']['communities'] = communities
                self.vars['data']['JP']['last_updated'] = last_updated
                self.vars['data']['JP']['prefix'] = prefix
                self.vars['data']['JP']['peer'] = peer
                self.vars['data']['JP']['origin'] = origin
                self.vars['data']['JP']['next_hop'] = next_hop
                self.vars['data']['JP']['latest_poll'] = latest_poll
        