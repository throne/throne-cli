# LICENSED UNDER BSD-3-CLAUSE-CLEAR LICENSE
# SEE PROVIDED LICENSE FILE IN ROOT DIRECTORY

# Import Third Party Modules
import logging
import click
import os
import yaml
from requests import request
# Import Throne Modules
from src.bgp import asn as get_asn

# Set log variable for verbose output
log = logging.getLogger(__name__)

# Get home directory
home = os.environ['HOME']
config_file = f'{home}/.throne/config.yml'

try:
    config = yaml.safe_load(open(config_file))
    throne_apikey = config['throne_key']
except:
    throne_apikey = None

# ARIN BOOTSTRAP URL
BOOTSTRAP_URL = 'https://rdap-bootstrap.arin.net/bootstrap'
RIPENETINFO_URL = 'https://stat.ripe.net/data/network-info/data.json?resource='
RIPEPREFIXOVER_URL = 'https://stat.ripe.net/data/prefix-overview/data.json?resource='
THRONE_API = 'https://api.throne.dev/'

@click.group()
def ip():
    """
    Retrieve IP related information.
    """
    pass

@ip.command(hidden=True)
@click.argument('address', nargs=1, metavar="IP_ADDRESS")
def raw(address):
    """
    This command prints raw JSON information for IP addresses. \n
    This raw output does NOT contain BGP related information.
    """
    throne_url = '{0}whois/ip?query={1}'.format(THRONE_API, address)
    throne_headers = {'Authorization': f'{throne_apikey}'}
    throne_response = request("GET", throne_url, headers=throne_headers)
    throne_result = throne_response.json()
    print(throne_result)

@ip.command()
@click.argument('address', nargs=1, metavar="IP_ADDRESS")
def geo(address):
    """
    Retrieves geolocation information for a specified IP address.
    """
    if "/" in address:
        click.secho("That looks like a prefix...try an address.", fg='red')
    else:
        # URLs
        url = f"http://ip-api.com/json/{address}"
        # Get/Parse Response
        response = request("GET", url)
        if response.status_code == 200:
            json = response.json()
            countryCode = json['countryCode']
            region = json['region']
            city = json['city']
            lat = json['lat']
            lon = json['lon']
            timezone = json['timezone']
            isp = json['isp']
            org = json['org']
            asnum = json['as']
            query = json['query']
            # Output to user
            click.echo(f"IP Address: {query} \nAS Number: {asnum} \nISP: {isp} \nOrganization: {org}")
            click.echo("---")
            click.echo(f"Location: {city}, {region}, {countryCode} \nLat/Long: {lat}/{lon} \nTimezone: {timezone}")

@ip.command()
@click.option("--all", "-a", is_flag=True, help="Gets IP + BGP info", default=False)
@click.argument('ipaddress', nargs=1, metavar="IP_OR_PREFIX")
@click.pass_context
def info(ctx, ipaddress, all):
    """
    Retrieves IP and registered contact information.
    """
    if throne_apikey:
        # Throne API Query
        throne_url = '{0}whois/ip?query={1}'.format(THRONE_API, ipaddress)
        throne_headers = {'Authorization': f'{throne_apikey}'}
        throne_response = request("GET", throne_url, headers=throne_headers)
        throne_result = throne_response.json()
        # RIPE API Query
        ripe_url = '{0}{1}'.format(RIPEPREFIXOVER_URL, ipaddress)
        ripe_response = request("GET", ripe_url)
        ripe_result = ripe_response.json()
        # Parsing responses
        if ripe_result['data']['asns'] is None:
            asnstr = "None"
        else:
            for asn in ripe_result['data']['asns']:
                asnstr = asn['asn']
                holderstr = asn['holder']
        # Output to user
        click.secho("---IP Info---", fg='green')
        click.echo(f"RIR: {throne_result['rir']}\nIssued By: {ripe_result['data']['block']['desc']}\nName: {throne_result['name']}\n Announced: {ripe_result['data']['announced']}\n Announced By: {asnstr} / {holderstr}\n Version: {throne_result['ipVersion']}\n Beginning: {throne_result['startAddress']}\n Ending: {throne_result['endAddress']}")
        click.secho(f'---{throne_result["rir"]}/{holderstr} Contact Information---', fg='green')
        for ent in throne_result['entities']:
            name = ent['name']
            type = ent['roles']
            delimeter = "/"
            if ent['roles'] is None:
                pass
            else:
                type = delimeter.join(type).title()
            click.secho(f'{name} ({type}):')
            if "RIPE" in throne_result['rir']:
                click.echo(" Entity Address: " + ent['address'] + "\n Entity Phone: " + str(ent['phone']) + "\n Entity Email: " + ent['email'])
                click.secho("\nSome of these details may be filtered by RIPE. To verify this information please visit https://apps.db.ripe.net/db-web-ui/query.", fg='red')
            else:
                click.echo(" Entity Address: " + ent['address'] + "\n Entity Phone: " + str(ent['phone']) + "\n Entity Email: " + ent['email'])
        if all:
            if ripe_result['data']['asns'] is None:
                click.secho("\nThis prefix appears to not be advertised. There are no related ASNs to get BGP info for.", fg='red')
            # Otherwise send ASNs to asn command in bgp.py
            else:
                for asn in ripe_result['data']['asns']:
                    asnstr = asn['asn']
                    ctx.invoke(get_asn, as_number=asnstr)
        else:
            pass
    if throne_apikey is None:
        click.secho("throne API key required! Run `throne api set` to configure your API key.", fg="red")
        click.secho("If you do not have an account, please register for one by visting https://api.throne.dev/auth/login and click 'Sign Up' at the bottom of the prompt", fg="red")