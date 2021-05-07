# LICENSED UNDER BSD-3-CLAUSE-CLEAR LICENSE
# SEE PROVIDED LICENSE FILE IN ROOT DIRECTORY

# Import Third Party Modules
import logging
import click
import yaml
import os
from requests import request
# Import Throne Modules
from src.parsers import json_request, shodan_parser
from src.exceptions import (ThroneParsingError, ThroneFormattingError, ThroneLookupFailed, ThroneHTTPError, ThroneConfigError)

# Set log variable for verbose output
log = logging.getLogger(__name__)

# Get home directory
home = os.path.expanduser("~")

try:
    config = yaml.safe_load(open(f'{home}/.throne/config.yml'))
    shodan_apikey = config['shodan_key']
except:
    pass

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

@shodan.command()
def setapi():
    """
    Use this command to set your Shodan API key.
    """
    try:
        if not os.path.exists(f"{home}/.throne"):
            os.makedirs(f"{home}/.throne")
        apikey_input = input("Enter Shodan API Key: ")
        shodan_apikey = {'shodan_key': f"{apikey_input}"}
        with open(f"{home}/.throne/config.yml", 'w') as throne_config:
            yaml.dump(shodan_apikey, throne_config)
        click.secho("Successfully set Shodan API key.", fg="green")
    except:
        raise ThroneConfigError("Failed to set Shodan API key.")

@shodan.command(hidden=True)
@click.argument('address', nargs=1, metavar="IP_ADDRESS")
def test(address):
    """
    This command prints raw JSON information for IP addresses\n
    from Shodan.
    """
    url = '{0}{1}?key={2}'.format(SHODAN_HOST, address, shodan_apikey)
    response = json_request._JSONRequest().get_json(url=url)
    print(response)

@shodan.command()
@click.option('--raw', '-r', is_flag=True)
def info(raw):
    """
    Return information about the plan belonging to\n
    the provided API key.
    """
    try:
        url = '{0}?key={1}'.format(SHODAN_INFO, shodan_apikey)
    except NameError:
        raise ThroneConfigError("Is your API key set? Run `throne shodan setapi` to set your API key.")
    response = json_request._JSONRequest().get_json(url=url)
    parse_json = shodan_parser._APIInfo(response)
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
    try:
        url = '{0}myip?key={1}'.format(SHODAN_TOOLS, shodan_apikey)
    except NameError:
        raise ThroneConfigError("Is your API key set? Run `throne shodan setapi` to set your API key.")
    response = json_request._JSONRequest().get_json(url=url)
    if raw:
        click.echo(response)
    else:
        click.secho("---Public IP Address---", fg="green")
        click.echo(f"{response}")

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
    try:
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
    except NameError:
        raise ThroneConfigError("Is your API key set? Run `throne shodan setapi` to set your API key.")
    response = json_request._JSONRequest().get_json(url=url)
    parse_json = shodan_parser._DNS(json_result=response, query_type=query_type)
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
            domain_tags = ', '.join(results['tags'])
            subdomains = ', '.join(results['subdomains'])
            all_domains = []
            types = []
            records = []
            click.secho("Domain: ", fg="green", nl=False)
            click.echo(f"{results['domain']}")
            click.secho("Shodan Tags: ", fg="green", nl=False)
            click.echo(f"{domain_tags}")
            click.secho("Subdomains: ", fg="green", nl=False)
            click.echo(f"{subdomains}")
            for domains in results['records']:
                for domain in domains.items():
                    all_domains.append(domain[0])
                    for record in domain[1]:
                        records.append(record)
                        record_types = record['type']
                        if record_types not in types:
                            types.append(record_types)
                        else:
                            pass
            for domain in all_domains:
                click.secho(f"--{domain} Records--", fg="magenta")
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "A"):
                        click.echo("A Records:")
                        break
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "A"):
                        ports = ', '.join((str(x) for x in record['ports']))
                        if ports == "":
                            click.echo(f" Value: {record['value']} | Last Seen: {record['last_seen']}")
                        else:
                            click.echo(f" Value: {record['value']}", nl=False)
                            click.echo(f" | Ports Opened: {ports} | Last Seen: {record['last_seen']}")
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "AAAA"):
                        click.echo("AAAA Records:")
                        break
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "AAAA"):
                        ports = ', '.join((str(x) for x in record['ports']))
                        if ports == "":
                            click.echo(f" Value: {record['value']} | Last Seen: {record['last_seen']}")
                        else:
                            click.echo(f" Value: {record['value']}", nl=False)
                            click.echo(f" | Ports Opened: {ports} | Last Seen: {record['last_seen']}")
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "CNAME"):
                        click.echo("CNAME Records:")
                        break
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "CNAME"):
                        ports = ', '.join((str(x) for x in record['ports']))
                        if ports == "":
                            click.echo(f" Value: {record['value']} | Last Seen: {record['last_seen']}")
                        else:
                            click.echo(f" Value: {record['value']}", nl=False)
                            click.echo(f" | Ports Opened: {ports} | Last Seen: {record['last_seen']}")
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "MX"):
                        click.echo("MX Records:")
                        break
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "MX"):
                        ports = ', '.join((str(x) for x in record['ports']))
                        if ports == "":
                            click.echo(f" Value: {record['value']} | Last Seen: {record['last_seen']}")
                        else:
                            click.echo(f" Value: {record['value']}", nl=False)
                            click.echo(f" | Ports Opened: {ports} | Last Seen: {record['last_seen']}")
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "NS"):
                        click.echo("NS Records:")
                        break
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "NS"):
                        ports = ', '.join((str(x) for x in record['ports']))
                        if ports == "":
                            click.echo(f" Value: {record['value']} | Last Seen: {record['last_seen']}")
                        else:
                            click.echo(f" Value: {record['value']}", nl=False)
                            click.echo(f" | Ports Opened: {ports} | Last Seen: {record['last_seen']}")
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "PTR"):
                        click.echo("PTR Records:")
                        break
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "PTR"):
                        ports = ', '.join((str(x) for x in record['ports']))
                        if ports == "":
                            click.echo(f" Value: {record['value']} | Last Seen: {record['last_seen']}")
                        else:
                            click.echo(f" Value: {record['value']}", nl=False)
                            click.echo(f" | Ports Opened: {ports} | Last Seen: {record['last_seen']}")
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "CERT"):
                        click.echo("CERT Records:")
                        break
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "CERT"):
                        ports = ', '.join((str(x) for x in record['ports']))
                        if ports == "":
                            click.echo(f" Value: {record['value']} | Last Seen: {record['last_seen']}")
                        else:
                            click.echo(f" Value: {record['value']}", nl=False)
                            click.echo(f" | Ports Opened: {ports} | Last Seen: {record['last_seen']}")
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "SRV"):
                        click.echo("SRV Records:")
                        break
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "SRV"):
                        ports = ', '.join((str(x) for x in record['ports']))
                        if ports == "":
                            click.echo(f" Value: {record['value']} | Last Seen: {record['last_seen']}")
                        else:
                            click.echo(f" Value: {record['value']}", nl=False)
                            click.echo(f" | Ports Opened: {ports} | Last Seen: {record['last_seen']}")
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "TXT"):
                        click.echo("TXT Records:")
                        break
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "TXT"):
                        ports = ', '.join((str(x) for x in record['ports']))
                        if ports == "":
                            click.echo(f" Value: {record['value']} | Last Seen: {record['last_seen']}")
                        else:
                            click.echo(f" Value: {record['value']}", nl=False)
                            click.echo(f" | Ports Opened: {ports} | Last Seen: {record['last_seen']}")
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "SOA"):
                        click.echo("SOA Records:")
                        break
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "SOA"):
                        ports = ', '.join((str(x) for x in record['ports']))
                        if ports == "":
                            click.echo(f" Value: {record['value']} | Last Seen: {record['last_seen']}")
                        else:
                            click.echo(f" Value: {record['value']}", nl=False)
                            click.echo(f" | Ports Opened: {ports} | Last Seen: {record['last_seen']}")
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "DNSKEY"):
                        click.echo("DNSKEY Records:")
                        break
                for record in records:
                    if (record['domain'] == domain) and (record['type'] == "DNSKEY"):
                        ports = ', '.join((str(x) for x in record['ports']))
                        if ports == "":
                            click.echo(f" Value: {record['value']} | Last Seen: {record['last_seen']}")
                        else:
                            click.echo(f" Value: {record['value']}", nl=False)
                            click.echo(f" | Ports Opened: {ports} | Last Seen: {record['last_seen']}")

@shodan.command()
@click.option('--raw', '-r', is_flag=True)
@click.option('--all', '-a', is_flag=True)
@click.argument('query', metavar="query", nargs=1)
def search(query, raw, all):
    """
    Get information for a specified IP address.
    """
    url = '{0}{1}?key={2}'.format(SHODAN_HOST, query, shodan_apikey)
    response = json_request._JSONRequest().get_json(url=url)
    parse_json = shodan_parser._IPSearch(json_result=response, query=query)
    parse_json.parse()
    results = parse_json.vars
    if raw:
        click.echo(results)
    else:
        # Shared Variables
        comma = ", "
        # Top-Level (TL) Variables
        domains = ', '.join((str(x) for x in results['domains']))
        hostnames = ', '.join((str(x) for x in results['hostnames']))
        ports = ', '.join((str(x) for x in results['ports']))
        protocols = ', '.join((str(x) for x in results['protocols']))
        click.secho(f"---Shodan Results For {results['query']}---", fg="yellow")
        click.echo(f"Data Last Updated: {response['last_update']}")
        click.echo(f"ASN: {response['asn']}")
        click.echo(f"ISP: {response['isp']}")
        click.echo(f"Location: {results['location']}")
        click.echo(f" Lat/Long: {results['coords']}")
        click.echo(f"Domain(s): {domains}")
        click.echo(f"Hostname(s): {hostnames}")
        click.echo(f"Port(s): {ports}")
        click.echo(f"Found Protocols: {protocols}")
        for protocol in results['protocols']:
            click.secho(f"--{protocol} Information--", fg="yellow")
            for idx, entry in enumerate(results['data'][protocol]):
                hostnames = ', '.join((str(x) for x in entry['hostnames']))
                domains = ', '.join((str(x) for x in entry['domains']))
                if idx > 0:
                    click.echo("--")
                click.echo(f"IP: {entry['ip']}\nPort: {entry['port']}\nHostnames: {hostnames}\nDomains: {domains}")