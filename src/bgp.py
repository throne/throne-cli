# LICENSED UNDER BSD-3-CLAUSE-CLEAR LICENSE
# SEE PROVIDED LICENSE FILE IN ROOT DIRECTORY

# Import Third Party Modules
import click
import logging
import os
import yaml
from requests import request
from pathlib import Path
# Import Throne Modules
from src.parsers import json_request
from src.parsers import rdap_asn_parser as asn_parser
from src.parsers import lg_parser
from src.exceptions import ThroneLookupFailed

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
#THRONE_API = "https://api.throne.dev/"
THRONE_API = "http://10.0.3.18:8080/"
BOOTSTRAP_URL = 'https://rdap-bootstrap.arin.net/bootstrap'
RIPESTAT_ASOverview = 'https://stat.ripe.net/data/as-overview/data.json?resource='
THRONE_API = 'https://api.throne.dev/'

@click.group()
def bgp():
    """
    Retrieve BGP related information.
    """
    pass

@bgp.command()
@click.argument('as_number', nargs=1, metavar="ASNUM")
def asn(as_number):
    """
    Gets information on the specified AS number.
    """
    if throne_apikey:
        url = '{0}{1}'.format(RIPESTAT_ASOverview, as_number)
        response = json_request._JSONRequest().get_json(url=url)
        # Take RIPEStat JSON response and put it as the JSON variable
        json = response
        asn = json['data']['resource']
        as_block = json['data']['block']['resource']
        block_desc = json['data']['block']['desc']
        block_name = json['data']['block']['name']
        holder = json['data']['holder']
        announced = json['data']['announced']
        click.secho("---Basic ASN Info--", fg='green')
        click.echo(f"AS#: {asn}\nHolder: {holder}\nAnnounced: {announced}")
        click.secho("---AS Block Info---", fg='green')
        click.echo(f"AS Block: {as_block}\nName: {block_name}\nDescription: {block_desc}")   
        try:
            url = '{0}whois/asn?query={1}'.format(THRONE_API, as_number)
            headers = {'Authorization': f'{throne_apikey}'}
            response = request("GET", url, headers=headers)
            result = response.json()
            rir = result['rir']
            handle = result['handle']
            click.secho(f'---{rir}/{handle} Contact Information---', fg='green')
            if "RIPE" in rir:
                log.debug("Detected RIPE as RIR...all non-abuse contacts are filtered by RIPE. See RIPE database docs for more information.")
            for ent in result['entities']:
                name = ent['name']
                kind = ent['roles']
                delimeter = "/"
                kind = delimeter.join(kind).title()
                click.secho(f'{name} ({kind}):')
                if ent['email'] is not None:
                    email = ent['email']
                else:
                    email = "None"
                if ent['address'] is not None:
                    address = ent['address']
                else:
                    address = "None"
                if ent['phone'] is not None:
                    phone = ent['phone']
                else:
                    phone = "None"
                if "RIPE" in rir:
                    click.echo(" Entity Address: " + address + "\n Entity Phone: " + phone + "\n Entity Email: " + email)
                    click.secho("\nSome of these details may be filtered by RIPE. To verify this information please visit https://apps.db.ripe.net/db-web-ui/query.", fg='red')
                else:
                    click.echo(" Entity Address: " + address + "\n Entity Phone: " + phone + "\n Entity Email: " + email)
        except:
            raise ThroneLookupFailed("Failed to get additional RIR data.")
    if throne_apikey == None:
        click.secho("throne API key required! Run `throne api setapi` to configure your API key.", fg="red")
        click.secho("If you do not have an account, please register for one by visting https://api.throne.dev/auth/login and click 'Sign Up' at the bottom of the prompt", fg="red")

@bgp.command()
@click.argument('prefix', nargs=1, metavar="ADDRESS_OR_PREFIX")
def prefix(prefix):
    """
    Gets prefix information for specified prefix or ip address.
    """
    url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={prefix}"
    response = request("GET", url)
    if response.status_code == 200:
        json = response.json()
        prefix = json['data']['resource']
        asn_int = json['data']['asns'][0]['asn']
        asn = asn_int
        holder = json['data']['asns'][0]['holder']
        ip_block = json['data']['block']['resource']
        block_desc = json['data']['block']['desc']
        block_name = json['data']['block']['name']
        click.echo(f"Prefix: {prefix} \n Announced By: {asn} \n Holder: {holder}")
        click.echo("---")
        click.echo(f"IP Block: {ip_block} \n Name: {block_name} \n Description: {block_desc}")

@bgp.command()
@click.argument('address', nargs=1, metavar="ADDRESS_OR_PREFIX")
@click.option('--all', '-a', is_flag=True)
@click.option('--raw', '-r', is_flag=True)
@click.option(
    '--location',
    type=click.Choice(['US-NY', 'US-FL', 'US-CA', 'UK', 'NL', 'SG', 'DE', 'ZA', 'JP'], case_sensitive=False),
    help="Looking Glass Location",
    default='US-NY',
    show_default='US-NY'
)
def lg(address, location, all, raw):
    """
    BGP looking glass information based upon provided address or prefix
    """
    url = f"https://stat.ripe.net/data/looking-glass/data.json?resource={address}"
    response = json_request._JSONRequest().get_json(url=url)
    parse_json = lg_parser._LGParse(response)
    parse_json.parse()
    results = parse_json.vars
    if raw:
        click.echo(results)
    click.secho(f"---{address} Looking Glass Results---", fg="yellow")
    click.echo(f"Status: {results['query_info']['status']}\nCached: {results['cached']}\nResults Returned: {results['query_info']['time']}")
    if all:
        for entries in results['data']:
            click.secho(f"--{entries} Results--", fg="yellow")
            click.echo(f"Location: {results['data'][entries]['location']}\nPrefix: {results['data'][entries]['prefix']}\nOrigin: {results['data'][entries]['origin']}\nOrigin AS: {results['data'][entries]['origin_as']}")
            click.echo(f"Peer: {results['data'][entries]['peer']}\nNext Hop: {results['data'][entries]['next_hop']}\nAS Path: {results['data'][entries]['as_path']}\nBGP Communities: {results['data'][entries]['communities']}")
            click.echo(f"Last Updated: {results['data'][entries]['last_updated']}\nLast Poll (This Router): {results['data'][entries]['latest_poll']}")
    else:
        for entries in results['data']:
            if location == entries:
                click.secho(f"--{location} Results--", fg="yellow")
                click.echo(f"Location: {results['data'][location]['location']}\nPrefix: {results['data'][location]['prefix']}\nOrigin: {results['data'][location]['origin']}\nOrigin AS: {results['data'][location]['origin_as']}")
                click.echo(f"Peer: {results['data'][location]['peer']}\nNext Hop: {results['data'][location]['next_hop']}\nAS Path: {results['data'][location]['as_path']}\nBGP Communities: {results['data'][location]['communities']}")
                click.echo(f"Last Updated: {results['data'][location]['last_updated']}\nLast Poll (This Router): {results['data'][location]['latest_poll']}")
