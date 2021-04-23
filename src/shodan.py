# LICENSED UNDER BSD-3-CLAUSE-CLEAR LICENSE
# SEE PROVIDED LICENSE FILE IN ROOT DIRECTORY

# Import Third Party Modules
import logging
import click
import yaml
from requests import request
# Import Throne Modules
from src.parsers import json_request, shodan_parser
from src.exceptions import (ThroneParsingError, ThroneFormattingError, ThroneLookupFailed, ThroneHTTPError)

# Set log variable for verbose output
log = logging.getLogger(__name__)

# Set config file
config = yaml.safe_load(open('config/test-config.yml'))
shodan_apikey = config['shodan_key']

# URLs
SHODAN_HOST = 'https://api.shodan.io/shodan/host/'
SHODAN_INFO = 'https://api.shodan.io/api-info'
SHODAN_TOOLS = 'https://api.shodan.io/tools/'
SHODAN_DNS = 'https://api.shodan.io/dns/'

@click.group()
def shodan():
    """
    Retrieve information from Shodan.
    """
    pass

@shodan.command(hidden=False)
@click.argument('address', nargs=1, metavar="IP_ADDRESS")
def raw(address):
    """
    This command prints raw JSON information for IP addresses\n
    from Shodan.
    """
    url = '{0}{1}?key={2}'.format(SHODAN_HOST, address, shodan_apikey)
    response = json_request._JSONRequest().get_json(url=url)
    json = response
    print(json)

@shodan.command()
def info():
    """
    Return information about the plan belonging to\n
    the provided API key.
    """
    url = '{0}?key={1}'.format(SHODAN_INFO, shodan_apikey)
    response = json_request._JSONRequest().get_json(url=url)
    json = response
    parse_json = shodan_parser._APIInfo(json)
    parse_json.parse()
    result = parse_json.vars
    click.secho("---Shodan API Info---", fg="green")
    click.echo(f"Shodan API Plan: {result['plan'].upper()}")
    click.echo(f"Total Scan Credits: {result['scan_limit']}\n Used Credits: {result['used_scan_credits']}\n Unused Credits: {result['scan_credits']}")
    click.echo(f"Total Query Credits {result['query_limit']}\n Used Credits: {result['used_query_credits']}\n Unused Credits: {result['query_credits']}")
    click.echo(f"Monitored IPs: {result['monitored_ips']}\n Monitored IP Limit: {result['ip_limit']}")
    click.echo(f"Unlocked: {result['unlocked']}\n Unlocked Left: {result['unlocked_left']}")

@shodan.command()
def myip():
    """
    Get your current public IP address.
    """
    url = '{0}myip?key={1}'.format(SHODAN_TOOLS, shodan_apikey)
    response = json_request._JSONRequest().get_json(url=url)
    json = response
    click.secho("---Public IP Address---", fg="green")
    click.echo(f"{json}")

@shodan.command()
@click.option(
    '--query-type',
    '-q', 
    type=click.Choice(['resolve', 'reverse', 'domain'], case_sensitive=False),
    help="Query type: Resolve DNS, Resolve Reverse DNS, or Get Domain Information"
    )
@click.argument('query', metavar="query")
def dns(query_type, query):
    """
    Host to IP, IP to Host, Domain DNS information.
    """
    if query_type == None:
        click.secho("You must specify a --query-type/-q option! View 'throne shodan dns --help' for more information.", fg="red")
        exit()
    elif "reverse" in query_type:
        url = '{0}reverse?ips={1}&key={2}'.format(SHODAN_DNS, query, shodan_apikey)
    elif "resolve" in query_type:
        url = '{0}resolve?hostnames={1}&key={2}'.format(SHODAN_DNS, query, shodan_apikey)
    elif "domain" in query_type:
        url = '{0}domain/{1}?key={2}'.format(SHODAN_DNS, query, shodan_apikey)
    response = json_request._JSONRequest().get_json(url=url)
    json = response
    print(json)
    
