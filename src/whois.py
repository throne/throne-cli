# LICENSED UNDER BSD-3-CLAUSE-CLEAR LICENSE
# SEE PROVIDED LICENSE FILE IN ROOT DIRECTORY

# Import Third Party Modules
import logging
import click
import yaml
import os
from requests import request
# Import Throne Modules

# Set log variable for verbose output
log = logging.getLogger(__name__)

# Get home directory
home = os.path.expanduser("~")
config_file = f'{home}/.throne/config.yml'

try:
    config = yaml.safe_load(open(config_file))
    throne_apikey = config['throne_key']
except:
    throne_apikey = None

# URLs
THRONE_API = "https://api.throne.dev/"
#THRONE_API = "https://dev-api.throne.dev/"

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
    if throne_apikey:
        url = "{}whois/domain?query={}".format(THRONE_API, domain)
        headers = {'Authorization': f'{throne_apikey}'}
        response = request("GET", url, headers=headers)
        result = response.json()
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
                        if data['name'] is None:
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
    if throne_apikey is None:
        click.secho("throne API key required! Run `throne api setapi` to configure your API key.", fg="red")
        click.secho("If you do not have an account, please register for one by visting https://api.throne.dev/auth/login and click 'Sign Up' at the bottom of the prompt", fg="red")