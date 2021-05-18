# LICENSED UNDER BSD-3-CLAUSE-CLEAR LICENSE
# SEE PROVIDED LICENSE FILE IN ROOT DIRECTORY

# Import Third Party Modules
import logging
import click
import yaml
import os
from requests import request
# Import Throne Modules
from src.parsers import json_request
from src.exceptions import (ThroneParsingError, ThroneFormattingError, ThroneLookupFailed, ThroneHTTPError, ThroneConfigError)

# Set log variable for verbose output
log = logging.getLogger(__name__)

# URLs
THRONE_API = "https://api.throne.dev/"

@click.group()
def whois():
    """
    Retrieve WHOIS information on domains.
    """
    pass

@whois.command()
@click.argument('domain', nargs=1, metavar="DOMAIN_NAME")
def domain(domain):
    """
    Get WHOIS information for a specified domain.
    """
    url = "{}api/whois?domain={}".format(THRONE_API, domain)
    result = json_request._JSONRequest().get_json(url=url)
    # Variables
    domain_status = ', '.join(result['status'])
    nameservers = ', '.join(result['whois']['nameservers'])
    click.secho(f"---{result['domain']} WHOIS Information---", fg="yellow")
    click.echo(f"Domain: {result['domain']}")
    if domain_status !="":
        click.echo(f"Domain Status: {domain_status}")
    else:
        pass
    try:
        click.echo(f"Nameservers: {nameservers}")
    except:
        click.echo(f"Nameservers: No Nameservers Found.")
    try:
        for secure in result['whois']['dnssec']:
            if secure['signed'] == False:
                click.echo(f"DNSSEC Enabled?: {secure['signed']}")
            if secure['signed'] == True:
                for data in secure['dsData']:
                    click.echo(f"DNSSEC Enabled?: {secure['signed']}")
                    click.echo(f" Keytag: {data['keyTag']}\n Algorithm: {data['algorithm']}\n Digest: {data['digest']} \n Digest Type: {data['digestType']}")
    except:
        pass
    click.secho(f"--Contact Information--", fg="yellow")
    for contact in result['registrar']['contact_info']:
        click.secho(f"Registrar {contact.capitalize()} Contact Information:", fg="green")
        try:
            for data in result['whois']['contact_info']['registrar']:
                    if data['name'] == None:
                        click.echo(f" Name: {result['registrar']['name']}")
                    else:
                        click.echo(f" Name: {data['name']}")
                    if data['address'] != None:
                        click.echo(f" Address: {data['address']}")
        except KeyError:
            click.echo(f" Name: {result['registrar']['name']}")
        except:
            pass
        for data in result['registrar']['contact_info'][contact]:
            click.echo(f" Phone: {data['phone']}\n Email: {data['email']}")
    try:
        for contact in result['whois']['contact_info']:
            if "registrant" in contact:
                #contact = contact
                click.secho(f"{contact.capitalize()} Contact Information:", fg="green")
                for data in result['whois']['contact_info'][contact]:
                    if "null" in data['name']:
                        pass
                    else:
                        click.echo(f" Name: {data['name']}")
                    if "null" in data['org']:
                        pass
                    else:
                        click.echo(f" Org: {data['org']}")
                    if "null" in data['address']:
                        pass
                    else:
                        click.echo(f" Address: {data['address']}")
                    if "null" in data['phone']:
                        pass
                    else:
                        click.echo(f" Phone: {data['phone']}")
                    if "null" in data['email']:
                        pass
                    else:
                        click.echo(f" Email: {data['email']}")
    except:
        pass
    
    try:
        for contact in result['whois']['contact_info']:
            if "admin" in contact:
                #contact = contact
                click.secho(f"{contact.capitalize()} Contact Information:", fg="green")
                for data in result['whois']['contact_info'][contact]:
                    if "null" in data['name']:
                        pass
                    else:
                        click.echo(f" Name: {data['name']}")
                    if "null" in data['org']:
                        pass
                    else:
                        click.echo(f" Org: {data['org']}")
                    if "null" in data['address']:
                        pass
                    else:
                        click.echo(f" Address: {data['address']}")
                    if "null" in data['phone']:
                        pass
                    else:
                        click.echo(f" Phone: {data['phone']}")
                    if "null" in data['email']:
                        pass
                    else:
                        click.echo(f" Email: {data['email']}")
    except:
        pass

    try:
        for contact in result['whois']['contact_info']:
            if "tech" in contact:
                #contact = contact
                click.secho(f"{contact.capitalize()} Contact Information:", fg="green")
                for data in result['whois']['contact_info'][contact]:
                    if "null" in data['name']:
                        pass
                    else:
                        click.echo(f" Name: {data['name']}")
                    if "null" in data['org']:
                        pass
                    else:
                        click.echo(f" Org: {data['org']}")
                    if "null" in data['address']:
                        pass
                    else:
                        click.echo(f" Address: {data['address']}")
                    if "null" in data['phone']:
                        pass
                    else:
                        click.echo(f" Phone: {data['phone']}")
                    if "null" in data['email']:
                        pass
                    else:
                        click.echo(f" Email: {data['email']}")
    except:
        pass

    try:
        if result['whois']['registration_info'] != {}:
            click.secho(f"--Registration Info--", fg="yellow")
            if result['whois']['registration_info']['expiration'] != "":
                click.echo(f"Expiration Date: {result['whois']['registration_info']['expiration']}")
            if result['whois']['registration_info']['registration'] != "":
                click.echo(f"Registration Date: {result['whois']['registration_info']['registration']}")
    except:
        pass