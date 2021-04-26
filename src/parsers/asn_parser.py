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

# RDAP & RIPESTAT URLs
BOOTSTRAP_URL = 'https://rdap-bootstrap.arin.net/bootstrap'
AFRNIC_URL = 'https://rdap.afrinic.net/rdap'
RIPESTAT_URL = 'https://stat.ripe.net/data'

# Set python check interval to 1, hopefully to improve performance
sys.setswitchinterval(1)

####################THIS LINE SEPERATES RDAP PARSERS FROM OTHER ASN PARSERS####################
class _RDAPASCommon:
    # This class is used to parse common data between AS number entities (see vars)
    def __init__(self, json_result):
        self.json = json_result
        self.vars = {
            'rir': None,
            'name': None
        }
    # This function takes our JSON response key/values and ties them to the self.vars key/values
    def _parse(self):
        log.debug("Parsing common varibles: RIR and Name...")
        # This in particular is taking ripe from "whois.ripe.net" and making it RIPE, a value of the "rir" variable
        rir = self.json['port43'].strip('whois')
        rir = rir.strip('net')
        rir = rir.strip('.')
        rir = rir.upper()
        self.vars['rir'] = rir
        self.vars['name'] = self.json['name']
        log.debug("Sending parsed JSON back to requesting module for user display...")

class _RDAPASEntity(_RDAPASCommon):
    # This class is used to parse data received from AS entities into specified vars
    def __init__(self, json_result):
        try:
            log.debug("Sending JSON to _RDAPASCommon to prepare parsing...")
            _RDAPASCommon.__init__(self, json_result)
        except ValueError:
            log.debug("_RDAPASCommon failed to parse, JSON received must not be a dict...")
            raise ThroneParsingError("JSON result is not a dict!")
        
        self.vars.update({
            'entities': []
        })
    # This function actually doesn't do much other than parsing other received data
    # from _RDAPContact into an overall JSON dictionary
    def parse(self):
            try:
                log.debug("Setting handle from JSON response...")
                self.vars['handle'] = self.json['handle'].strip()
            except:
                log.debug("Handle missing from RDAP entity...raising exception")
                raise ThroneParsingError("Handle missing from RDAP entity")
            # There's probably a WAAAYYY better way to do what I'm doing below, this got it working.
            # I'm looking for each RIR in the port43 key of the JSON response. ARIN and AFRINIC had
            # to be special and not format things in the same way as RIPE or APNIC. LACNIC info is
            # still pending...trying to figure out how that works.
            try:
                log.debug("Trying to parse entity data based upon RIRs format...")
                # Parse RIPE formatted data
                if "ripe" in self.json['port43']:
                    log.debug("RIPE detected as responding RIR...")
                    for ent in self.json['entities']:
                            try:
                                vcard = ent['vcardArray'][1]
                                c = _RDAPContact(vcard)
                                c.parse()
                                c.vars['roles'] = ent['roles']
                                log.debug("Appending all parsed vCardArrays to vars['entities']...")
                                self.vars['entities'].append(c.vars)
                            except:
                                log.debug("There might be more data for this ASN...RIPE filters all contacts except abuse contacts. Filtered contacts are not displayed.")
                                pass
                # Parse APNIC formatted data
                if "apnic" in self.json['port43']:
                    log.debug("APNIC detected as responding RIR...")
                    for ent in self.json['entities']:
                            try:
                                vcard = ent['vcardArray'][1]
                                c = _RDAPContact(vcard)
                                c.parse()
                                c.vars['roles'] = ent['roles']
                                log.debug("Appending all parsed vCardArrays to vars['entities']...")
                                self.vars['entities'].append(c.vars)
                            except:
                                log.debug("Additional ASN contact information found but skipping it. Please report this with all debug logs as an issue for Throne.")
                            pass
                # Parse ARIN formatted data
                if "arin" in self.json['port43']:
                    log.debug("ARIN detected as responding RIR...")
                    for ent in self.json['entities']:
                            try:
                                vcard = ent['vcardArray'][1]
                                c = _RDAPContact(vcard)
                                c.parse()
                                c.vars['roles'] = ent['roles']
                                log.debug("Appending all parsed vCardArrays to vars['entities']...")
                                self.vars['entities'].append(c.vars)
                            except:
                                log.debug("Additional ASN contact information found but skipping it. Please report this with all debug logs as an issue for Throne.")
                            pass
                    log.debug("ARIN likes to be special and nest entities, attempting to parse those...")
                    for ent in self.json['entities'][0]['entities']:
                            try:
                                vcard = ent['vcardArray'][1]
                                c = _RDAPContact(vcard)
                                c.parse()
                                c.vars['roles'] = ent['roles']
                                log.debug("Appending all parsed vCardArrays to vars['entities']...")
                                self.vars['entities'].append(c.vars)
                            except:
                                log.debug("Additional ARIN nested contact information found but skipping it. Please report this with all debug logs as an issue for Throne.")
                                pass
                # Parse AFRINIC formatted data
                if "afrinic" in self.json['port43']:
                    log.debug("AFRINIC detected as responding RIR...")
                    for ent in self.json['entities']:
                        try:
                            vcard = ent['vcardArray'][1]
                            c = _RDAPContact(vcard)
                            c.parse()
                            c.vars['roles'] = ent['roles']
                            log.debug("Appending all parsed vCardArrays to vars['entities']...")
                            self.vars['entities'].append(c.vars)
                        except:
                            log.debug("Additional ASN contact information found but skipping it. Please report this with all debug logs as an issue for Throne.")
                            pass
                # Placeholder for future LACNIC data
            except:
                log.debug("Cannot parse the vCardArry for entities, raising exception")
                raise ThroneParsingError("vcardArray parsing failed!")
                
            # If we don't get a self.vars['entities'] response just set it to None
            if not self.vars['entities']:
                self.vars['entities'] = None

            log.debug("Asking _RDAPASCommon to parse common variables")
            self._parse()
        
class _RDAPContact:
    # This class is used to parse the vcardArray out of each entity as specified above.
    # Each key/value in the JSON response has it's own function to ultimately place it
    # into custom JSON keys/values
    def __init__(self, vcard):
        self.vcard = vcard
        self.vars = {
            'name': None,
            'kind': None,
            'address': None,
            'phone': None,
            'email': None,
            'roles': None,
            'title': None
        }

    def _parse_name(self, val):
        """
        Parses names out of vCard
        """
        self.vars['name'] = val[3].strip()

    def _parse_kind(self, val):
        self.vars['kind'] = val[3].strip()

    def _parse_address(self, val):
        answer = {
            'type': None,
            'value': None
        }

        try:
            answer['type'] = val[1]['type']
        except:
            pass

        try:
            answer['value'] = val[1]['label'].replace("\n", " ")
        except:
            answer['value'] = '\n'.join(val[3]).strip()
        try:
            self.vars['address'].append(answer)
        except:
            self.vars['address'] = []
            self.vars['address'].append(answer)

    def _parse_phone(self, val):
        answer = {
            'type': None,
            'value': None 
        }

        try:
            answer['type'] = val[1]['type']
        except:
            pass
        
        answer['value'] = val[3]

        try:
            self.vars['phone'].append(answer)
        except:
            self.vars['phone'] = []
            self.vars['phone'].append(answer)
    def _parse_email(self, val):
        answer = {
            'type': None,
            'value': None
        }

        try:
            answer['type'] = val[1]['type']
        except:
            pass

        answer['value'] = val[3].strip()

        try:
            self.vars['email'].append(answer)
        except:
            self.vars['email'] = []
            self.vars['email'].append(answer)

    def _parse_role(self, val):
        self.vars['roles'] = val[3]

    def _parse_title(self, val):
        self.vars['title'] = val[3]

    def parse(self):
        # Custom Keys
        keys = {
            'fn': self._parse_name,
            'kind': self._parse_kind,
            'adr': self._parse_address,
            'tel': self._parse_phone,
            'email': self._parse_email,
            'role': self._parse_role,
            'title': self._parse_title
        }
        # Take all values from the above functions and add to
        # the appropriate keys
        for val in self.vcard:
            try:
                parser = keys.get(val[0])
                parser(val)
                log.debug(f"Parsing {val}...")
            except:
                pass
####################THIS LINE SEPERATES RDAP PARSERS FROM OTHER ASN PARSERS####################

class _RIPESTATParser:
    def __init__(self):
        pass