# LICENSED UNDER BSD-3-CLAUSE-CLEAR LICENSE
# SEE PROVIDED LICENSE FILE IN ROOT DIRECTORY

# Import Third Party Modules
import click
import logging
import sys
from requests import request
# Import Throne Modules
from src.parsers import json_request
from src.parsers import rdap_asn_parser as asn_parser
from src.exceptions import (ThroneParsingError, ThroneFormattingError, ThroneLookupFailed, ThroneHTTPError)

# Set log variable for verbose output
log = logging.getLogger(__name__)

BOOTSTRAP_URL = 'https://rdap-bootstrap.arin.net/bootstrap'
RIPESTAT_ASOverview = 'https://stat.ripe.net/data/as-overview/data.json?resource='

@click.group()
def bgp():
    """
    Retrieve BGP related information.
    """
    pass

@bgp.command(hidden=True)
@click.argument('as_number', nargs=1, metavar="ASNUM")
def raw(as_number):
    """
    Get raw JSON output from asn_parser.py
    """
    url = '{0}/autnum/{1}'.format(BOOTSTRAP_URL, as_number)
    response = json_request._JSONRequest().get_json(url=url)
    json = response
    parse_json = asn_parser._RDAPASEntity(json)
    parse_json.parse()
    result = parse_json.vars
    click.echo(result)

@bgp.command(hidden=True)
@click.argument('as_number', nargs=1, metavar="ASNUM")
def test(as_number):
    """
    Test parsing
    """
    # Get AS Number JSON via src/parser/asn_parser.py
    url = '{0}/autnum/{1}'.format(BOOTSTRAP_URL, as_number)
    response = json_request._JSONRequest().get_json(url=url)
    json = response
    # Parse JSON response using the asn_parser parser
    parse_json = asn_parser._RDAPASEntity(json)
    parse_json.parse()
    result = parse_json.vars
    # Get RIR Name
    rir = result['rir']
    # Assign JSON keys/values to variables
    handle = result['handle']
    for ent in result['entities']:
        if 'abuse' in ent['roles']:
            for email in ent['email']:
                abuse_email = email['value']
    click.echo(f"---{rir} Information---")
    click.echo(f"AS# {handle}\nAbuse Email: {abuse_email}")

@bgp.command()
@click.argument('as_number', nargs=1, metavar="ASNUM")
def asn(as_number):
    """
    Gets information on the specified AS number.
    """
    # Get Info from RIPEStat
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
        url = '{0}/autnum/{1}'.format(BOOTSTRAP_URL, as_number)
        response = json_request._JSONRequest().get_json(url=url)
        json = response
        parse_json = asn_parser._RDAPASEntity(json)
        parse_json.parse()
        result = parse_json.vars
        log.debug("Received parsed JSON back from asn_parser.py...")
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
            try:
                for email in ent['email']:
                    email = email['value']
            except:
                email = "None"
            try:
                for address in ent['address']:
                    address = address['value']
            except:
                address = "None"
            try:
                for phone in ent['phone']:
                    phone = phone['value']
            except:
                phone = "None"
            if "RIPE" in rir:
                click.echo(" Entity Address: " + address + "\n Entity Phone: " + phone + "\n Entity Email: " + email)
                click.secho("\nSome of these details may be filtered by RIPE. To verify this information please visit https://apps.db.ripe.net/db-web-ui/query.", fg='red')
            else:
                click.echo(" Entity Address: " + address + "\n Entity Phone: " + phone + "\n Entity Email: " + email)
    except:
        raise ThroneLookupFailed("Failed to get additional RIR data.")

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
@click.option(
    '--location',
    type=click.Choice(['US-NY', 'US-FL', 'US-CA', 'UK', 'NL', 'SG', 'DE', 'ZA', 'JP'], case_sensitive=False),
    help="Looking Glass Location",
    default='US-NY',
    show_default='US-NY'
)
def look(address,location):
    """
    BGP looking glass information based upon provided address or prefix
    """
    url = f"https://stat.ripe.net/data/looking-glass/data.json?resource={address}"
    response = request("GET", url)
    if response.status_code == 200:
        json = response.json()
        if location == 'US-NY':
            location = json['data']['rrcs'][17]['location']
            peer = json['data']['rrcs'][17]['peers'][0]['peer']
            prefix = json['data']['rrcs'][17]['peers'][0]['prefix']
            as_origin = json['data']['rrcs'][17]['peers'][0]['asn_origin']
            as_path = json['data']['rrcs'][17]['peers'][0]['as_path']
            click.echo(f"Peer: {peer}\n Peer Location: {location}")
            click.echo("---")
            click.echo(f"Origin AS: {as_origin} \n Prefix: {prefix} \n AS Path: {as_path}")
        if location == 'US-FL':
            location = json['data']['rrcs'][19]['location']
            peer = json['data']['rrcs'][19]['peers'][0]['peer']
            prefix = json['data']['rrcs'][19]['peers'][0]['prefix']
            as_origin = json['data']['rrcs'][19]['peers'][0]['asn_origin']
            as_path = json['data']['rrcs'][19]['peers'][0]['as_path']
            click.echo(f"Peer: {peer}\n Peer Location: {location}")
            click.echo("---")
            click.echo(f"Origin AS: {as_origin} \n Prefix: {prefix} \n AS Path: {as_path}")
        if location == 'US-CA':
            location = json['data']['rrcs'][18]['location']
            peer = json['data']['rrcs'][18]['peers'][0]['peer']
            prefix = json['data']['rrcs'][18]['peers'][0]['prefix']
            as_origin = json['data']['rrcs'][18]['peers'][0]['asn_origin']
            as_path = json['data']['rrcs'][18]['peers'][0]['as_path']
            click.echo(f"Peer: {peer}\n Peer Location: {location}")
            click.echo("---")
            click.echo(f"Origin AS: {as_origin} \n Prefix: {prefix} \n AS Path: {as_path}")
        if location == 'UK':
            location = json['data']['rrcs'][1]['location']
            peer = json['data']['rrcs'][1]['peers'][0]['peer']
            prefix = json['data']['rrcs'][1]['peers'][0]['prefix']
            as_origin = json['data']['rrcs'][1]['peers'][0]['asn_origin']
            as_path = json['data']['rrcs'][1]['peers'][0]['as_path']
            click.echo(f"Peer: {peer}\n Peer Location: {location}")
            click.echo("---")
            click.echo(f"Origin AS: {as_origin} \n Prefix: {prefix} \n AS Path: {as_path}")
        if location == 'NL':
            location = json['data']['rrcs'][0]['location']
            peer = json['data']['rrcs'][0]['peers'][0]['peer']
            prefix = json['data']['rrcs'][0]['peers'][0]['prefix']
            as_origin = json['data']['rrcs'][0]['peers'][0]['asn_origin']
            as_path = json['data']['rrcs'][0]['peers'][0]['as_path']
            click.echo(f"Peer: {peer}\n Peer Location: {location}")
            click.echo("---")
            click.echo(f"Origin AS: {as_origin} \n Prefix: {prefix} \n AS Path: {as_path}")
        if location == 'SG':
            location = json['data']['rrcs'][3]['location']
            peer = json['data']['rrcs'][3]['peers'][0]['peer']
            prefix = json['data']['rrcs'][3]['peers'][0]['prefix']
            as_origin = json['data']['rrcs'][3]['peers'][0]['asn_origin']
            as_path = json['data']['rrcs'][3]['peers'][0]['as_path']
            click.echo(f"Peer: {peer}\n Peer Location: {location}")
            click.echo("---")
            click.echo(f"Origin AS: {as_origin} \n Prefix: {prefix} \n AS Path: {as_path}")
        if location == 'DE':
            location = json['data']['rrcs'][4]['location']
            peer = json['data']['rrcs'][4]['peers'][0]['peer']
            prefix = json['data']['rrcs'][4]['peers'][0]['prefix']
            as_origin = json['data']['rrcs'][4]['peers'][0]['asn_origin']
            as_path = json['data']['rrcs'][4]['peers'][0]['as_path']
            click.echo(f"Peer: {peer}\n Peer Location: {location}")
            click.echo("---")
            click.echo(f"Origin AS: {as_origin} \n Prefix: {prefix} \n AS Path: {as_path}")
        if location == 'ZA':
            location = json['data']['rrcs'][16]['location']
            peer = json['data']['rrcs'][16]['peers'][0]['peer']
            prefix = json['data']['rrcs'][16]['peers'][0]['prefix']
            as_origin = json['data']['rrcs'][16]['peers'][0]['asn_origin']
            as_path = json['data']['rrcs'][16]['peers'][0]['as_path']
            click.echo(f"Peer: {peer}\n Peer Location: {location}")
            click.echo("---")
            click.echo(f"Origin AS: {as_origin} \n Prefix: {prefix} \n AS Path: {as_path}")
        if location == 'JP':
            location = json['data']['rrcs'][20]['location']
            peer = json['data']['rrcs'][20]['peers'][0]['peer']
            prefix = json['data']['rrcs'][20]['peers'][0]['prefix']
            as_origin = json['data']['rrcs'][20]['peers'][0]['asn_origin']
            as_path = json['data']['rrcs'][20]['peers'][0]['as_path']
            click.echo(f"Peer: {peer}\n Peer Location: {location}")
            click.echo("---")
            click.echo(f"Origin AS: {as_origin} \n Prefix: {prefix} \n AS Path: {as_path}")