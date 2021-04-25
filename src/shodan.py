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
def test(address):
    """
    This command prints raw JSON information for IP addresses\n
    from Shodan.
    """
    url = '{0}{1}?key={2}'.format(SHODAN_HOST, address, shodan_apikey)
    response = json_request._JSONRequest().get_json(url=url)
    json = response
    print(json)

@shodan.command()
@click.option('--raw', '-r', is_flag=True)
def info(raw):
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
    if raw:
        click.echo(result)
    else:
        click.secho("---Shodan API Info---", fg="green")
        click.echo(f"Shodan API Plan: {result['plan'].upper()}")
        click.echo(f"Total Scan Credits: {result['scan_limit']}\n Used Credits: {result['used_scan_credits']}\n Unused Credits: {result['scan_credits']}")
        click.echo(f"Total Query Credits {result['query_limit']}\n Used Credits: {result['used_query_credits']}\n Unused Credits: {result['query_credits']}")
        click.echo(f"Monitored IPs: {result['monitored_ips']}\n Monitored IP Limit: {result['ip_limit']}")
        click.echo(f"Unlocked: {result['unlocked']}\n Unlocked Left: {result['unlocked_left']}")

@shodan.command()
@click.option('--raw', '-r', is_flag=True)
def myip(raw):
    """
    Get your current public IP address.
    """
    url = '{0}myip?key={1}'.format(SHODAN_TOOLS, shodan_apikey)
    response = json_request._JSONRequest().get_json(url=url)
    json = response
    if raw:
        click.echo(json)
    else:
        click.secho("---Public IP Address---", fg="green")
        click.echo(f"{json}")

@shodan.command()
@click.option(
    '--query-type',
    '-q', 
    type=click.Choice(['resolve', 'reverse', 'domain'], case_sensitive=False),
    help="Query type: Resolve DNS, Resolve Reverse DNS, or Get Domain Information"
    )
@click.option('--raw', '-r', is_flag=True)
@click.argument('query', metavar="query", nargs=-1)
def dns(query_type, query, raw):
    """
    Host to IP, IP to Host, Domain DNS information.
    """
    query_list = []
    for domain in query:
        query_list.append(domain)
        query = ','.join(query_list)
    if query_type == None:
        click.secho("You must specify a --query-type/-q option! View 'throne shodan dns --help' for more information.", fg="red")
        exit()
    elif "reverse" in query_type:
        url = '{0}reverse?ips={1}&key={2}'.format(SHODAN_DNS, query, shodan_apikey)
    elif "domain" in query_type:
        if len(query_list) > 1:
            raise ThroneFormattingError("Only 1 domain can be specified! Remove the others and try again.")
        url = '{0}domain/{1}?key={2}'.format(SHODAN_DNS, query, shodan_apikey)
    elif "resolve" in query_type:
        url = '{0}resolve?hostnames={1}&key={2}'.format(SHODAN_DNS, query, shodan_apikey)
    response = json_request._JSONRequest().get_json(url=url)
    json = response
    parse_json = shodan_parser._DNS(json_result=json, query_type=query_type)
    parse_json.parse()
    results = parse_json.vars
    if raw:
        click.echo(results)
    else:
        click.secho("---Shodan DNS Results---", fg="yellow")
        if "reverse" in query_type:
            for result in results['result']:
                click.secho(f"{result['ip']}", fg="red", nl=False)
                click.secho(" resolves to ", nl=False)
                click.secho(f"{result['hostname']}", fg="red")
        if "resolve" in query_type:
            for result in results['result']:
                click.secho(f"{result['hostname']}", fg="red", nl=False)
                click.secho(" resolves to ", nl=False)
                click.secho(f"{result['ip']}", fg="red")
        if "domain" in query_type:
            print(results)
            print()
            domain_tags = ', '.join(results['tags'])
            subdomains = ', '.join(results['subdomains'])
            records_available = []
            click.secho(f"Domain: {results['domain']}\nShodan Tags: {domain_tags}\nSubdomains: {subdomains}")
            click.secho(f"--{query} Records--", fg="magenta")
            for record in results['records']:
                records_available.append(record['type'])
            if "NS" in records_available:
                click.secho("NS Record Value:")
                for record in results['records']:
                    record_tags = ', '.join(record['tags'])
                    ports = ', '.join((str(x) for x in record['ports']))
                    if record['domain'] == query:
                        if "NS" in record['type']:
                            click.secho(f" {record['value']}")
            else:
                pass
            if "A" in records_available or "AAAA" in records_available:
                click.secho("A/AAAA Record Value:")
                for record in results['records']:
                    record_tags = ', '.join(record['tags'])
                    ports = ', '.join((str(x) for x in record['ports']))
                    if record['domain'] == query:
                        if "A" in record['type'] or "AAAA" in record['type']:
                            click.secho(f" {record['value']}")
                            if ports == "":
                                pass
                            else:
                                click.echo(f" Ports Seen: {ports}")
            else:
                pass
            if "MX" in records_available:
                click.secho("MX Record Value:")
                for record in results['records']:
                    record_tags = ', '.join(record['tags'])
                    ports = ', '.join((str(x) for x in record['ports']))
                    if record['domain'] == query:
                        if "MX" in record['type']:
                            click.secho(f" {record['value']}")
            else:
                pass
            if "SOA" in records_available:
                click.secho("SOA Record Value:")
                for record in results['records']:
                    record_tags = ', '.join(record['tags'])
                    ports = ', '.join((str(x) for x in record['ports']))
                    if record['domain'] == query:
                        if "SOA" in record['type']:
                            click.secho(f" {record['value']}")
            else:
                pass
            if "TXT" in records_available:
                click.secho("TXT Record Value:")
                for record in results['records']:
                    record_tags = ', '.join(record['tags'])
                    ports = ', '.join((str(x) for x in record['ports']))
                    if record['domain'] == query:
                        if "TXT" in record['type']:
                            click.secho(f" {record['value']}")
            else:
                pass
            if "CNAME" in records_available:
                click.secho("CNAME Record Value:")
                for record in results['records']:
                    record_tags = ', '.join(record['tags'])
                    ports = ', '.join((str(x) for x in record['ports']))
                    if record['domain'] == query:
                        if "CNAME" in record['type']:
                            click.secho(f" {record['value']}")
            else:
                pass
            for subdomain in results['subdomains']:
                click.secho(f"--{subdomain} Records--", fg="magenta")
                if "A" in records_available or "AAAA" in records_available:
                    click.secho(f"A/AAAA Record Value:")
                    for record in results['records']:
                        record_tags = ', '.join(record['tags'])
                        ports = ', '.join((str(x) for x in record['ports']))
                        if record['domain'] == subdomain:
                            if "A" in record['type'] or "AAAA" in record['type']:
                                click.secho(f" {record['value']}")
                                if ports == "":
                                    pass
                                else:
                                    click.echo(f" Ports Seen: {ports}")
                else:
                    pass
                if "CNAME" in records_available:
                    click.secho(f"CNAME Record Value:")
                    for record in results['records']:
                        record_tags = ', '.join(record['tags'])
                        ports = ', '.join((str(x) for x in record['ports']))
                        if record['domain'] == subdomain:
                            if "CNAME" in record['type']:
                                click.secho(f" {record['value']}")
                            else:
                                pass
                else:
                    pass