#    Copyright (C) 2021  Dakota Gartley
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Import Third Party Modules
import logging
import click
from requests import request
# Import Throne Modules
from src.parsers import ip_parser
from src.bgp import asn as get_asn
from src.bgp import raw as get_asn_raw

# Set log variable for verbose output
log = logging.getLogger(__name__)

# ARIN BOOTSTRAP URL
BOOTSTRAP_URL = 'https://rdap-bootstrap.arin.net/bootstrap'
RIPENETINFO_URL = 'https://stat.ripe.net/data/network-info/data.json?resource='
RIPEPREFIXOVER_URL = 'https://stat.ripe.net/data/prefix-overview/data.json?resource='

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
    url = '{0}/ip/{1}'.format(BOOTSTRAP_URL, address)
    response = ip_parser._JSONRequest().get_json(url=url)
    json = response
    parse_json = ip_parser._RDAPIPEntity(json)
    parse_json.parse()
    results = parse_json.vars
    print(results)

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
    # URLs
    bootstrap_url = '{0}/ip/{1}'.format(BOOTSTRAP_URL, ipaddress)
    ripe_url = '{0}{1}'.format(RIPEPREFIXOVER_URL, ipaddress)
    # Parse Responses
    ## Bootstrap Response
    response_bootstrap = ip_parser._JSONRequest().get_json(url=bootstrap_url)
    bootstrap_json = response_bootstrap
    parse_bootstrap_json = ip_parser._RDAPIPEntity(bootstrap_json)
    parse_bootstrap_json.parse()
    bootstrap_results = parse_bootstrap_json.vars
    ## RIPE Response
    ripe_response = ip_parser._JSONRequest().get_json(url=ripe_url)
    ripe_json = ripe_response
    parse_ripe_json = ip_parser._RIPEPrefixOverview(ripe_json)
    parse_ripe_json.parse()
    ripe_results = parse_ripe_json.vars
    # Set Variables
    rir = bootstrap_results['rir']
    startAddress = bootstrap_results['startAddress']
    endAddress = bootstrap_results['endAddress']
    ipVersion = bootstrap_results['ipVersion']
    name = bootstrap_results['name']
    status = bootstrap_results['type']
    handle = bootstrap_results['handle']
    cidr = ripe_results['prefix']
    if ripe_results['asns'] == None:
        asnstr = "None"
    else:
        for asn in ripe_results['asns']:
            asnstr = asn['asn']
    announced = ripe_results['announced']
    # Meat & Potatos (Start outputing to user)
    click.secho("---IP Info---", fg='green')
    if "RIPE" in bootstrap_results['rir']:
        log.debug("RIPE detected as RIR. CIDR has been changed to 'Parent Handle'.")
        click.echo(f"Issued By: {rir}\nStatus: {status}\nName: {name}\nParent Handle: {cidr}\n Announced: {announced}\n Announced By: {asnstr}\n Version: {ipVersion}\n Beginning: {startAddress}\n Ending: {endAddress}")
    else:
        click.echo(f"Issued By: {rir}\nStatus: {status}\nName: {name}\nCIDR: {cidr}\n Announced: {announced}\n Announced By: {asnstr}\n Version: {ipVersion}\n Beginning: {startAddress}\n Ending: {endAddress}")
    click.secho(f'---{rir}/{handle} Contact Information---', fg='green')
    if "RIPE" in rir:
            log.debug("Detected RIPE as RIR...all non-abuse contacts are filtered by RIPE. See RIPE database docs for more information.")
    for ent in bootstrap_results['entities']:
        name = ent['name']
        kind = ent['roles']
        delimeter = "/"
        if ent['roles'] == None:
            pass
        else:
            kind = delimeter.join(kind).title()
        click.secho(f'{name} ({kind}):')
        try:
            for email in ent['email']:
                email = email['value']
        except:
            email = "None"
        try:
            for streetAddress in ent['address']:
                streetAddress = streetAddress['value']
        except:
            streetAddress = "None"
        try:
            for phone in ent['phone']:
                phone = phone['value']
        except:
            phone = "None"
        if "RIPE" in rir:
            click.echo(" Entity Address: " + streetAddress + "\n Entity Phone: " + phone + "\n Entity Email: " + email)
            click.secho("\nSome of these details may be filtered by RIPE. To verify this information please visit https://apps.db.ripe.net/db-web-ui/query.", fg='red')
        else:
            click.echo(" Entity Address: " + streetAddress + "\n Entity Phone: " + phone + "\n Entity Email: " + email)
    if all:
        if ripe_results['asns'] == None:
            click.secho("\nThis prefix appears to not be advertised. There are no related ASNs to get BGP info for.", fg='red')
            pass
        # Otherwise send ASNs to asn command in bgp.py
        else:
            for asn in ripe_results['asns']:
                asnstr = asn['asn']
                ctx.invoke(get_asn, as_number=asnstr)
    else:
        pass