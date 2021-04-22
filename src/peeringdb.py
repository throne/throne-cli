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
from src.exceptions import (ThroneParsingError, ThroneFormattingError, ThroneLookupFailed, ThroneHTTPError)
from src.parsers import asn_parser

# Set log variable for verbose output
log = logging.getLogger(__name__)

# URL Variables
PDB_ORG_ASN = "https://www.peeringdb.com/api/org?asn="
PDB_IX_NAME = "https://www.peeringdb.com/api/ix?name_search="

@click.group()
def pdb():
    """
    Retrieve information from PeeringDB.
    """
    pass

@pdb.command()
@click.argument('as_number', nargs=1, metavar="AS_NUM")
def asn(as_number):
    """
    Retrieves information about an organization by AS#.
    """
    url = "{0}{1}".format(PDB_ORG_ASN, as_number)
    response = asn_parser._JSONRequest().get_json(url=url)
    json = response
    if json['data'] == []:
        raise ThroneHTTPError(f"PeeringDB returned a blank result. Please check your query and try again. If the issue persists, manually query PeeringDB to see if the entry exists.\nJSON Returned: {json}")
    else:
        for v in json['data'][0].items():
            if v is not None:
                newdict = dict([(vkey, vdata) for vkey, vdata in json['data'][0].items() if(vdata)])
        click.secho("---PeeringDB Information---", fg="green")
        for k,v in newdict.items():
            k = k.capitalize()
            click.secho(f"{k}: {v}")
        click.secho("\nSome results may have been ommited due to having no value.", fg="red")

@pdb.command()
@click.option("--unformatted", "-u", is_flag=True, help="Returns output unformatted.", default=False)
@click.option("--count", "-c", help="Changes the number of results returned.", default=3, show_default=3, metavar="NUMBER")
@click.argument('ix', nargs=1, metavar="IX")
def ix(ix, unformatted, count):
    """
    Returns IX search output from PeeringDB.
    """
    url = "{0}{1}&limit={2}".format(PDB_IX_NAME, ix, count)
    response = asn_parser._JSONRequest().get_json(url=url)
    json = response
    if json['data'] == []:
        raise ThroneHTTPError(f"PeeringDB returned a blank result. Please check your query and try again. If the issue persists, manually query PeeringDB to see if the entry exists.\nJSON Returned: {json}")
    else:
        click.secho("---PeeringDB Results---", fg="green")
        if unformatted:
            for ix in json['data']:
                click.secho(f"--{ix['name']}--", fg="blue")
                for k,v in ix.items():
                    k = k.capitalize()
                    click.secho(f"{k}: {v}")
        else:
            for ix in json['data']:
                # Variables
                ix_city = ix['city']
                ix_country = ix['country']
                ix_tech_email = ix['tech_email']
                ix_tech_phone = ix['tech_phone']
                ix_policy_email = ix['policy_email']
                ix_policy_phone = ix['policy_phone']
                comma = ", "
                slash = "/"
                location = [ix_city, ix_country]
                location = comma.join(location)
                tech_contact = [ix_tech_email, ix_tech_phone]
                tech_contact = slash.join(tech_contact)
                policy_contact = [ix_policy_email, ix_policy_phone]
                policy_contact = slash.join(policy_contact)
                # Create supported protocol dictionary
                protocols = {
                    'Unicast IPv4': ix['proto_unicast'],
                    'Multicast': ix['proto_multicast'],
                    'IPv6': ix['proto_ipv6'],
                }
                # Parse created disctionary for protocols whos values = True
                protocols = {key for (key,value) in protocols.items() if value == True}
                # Join protocols with a slash (/)
                protocols = slash.join(protocols)
                # Print output
                click.secho(f"--{ix['name']}--", fg="blue")
                click.echo(f"Name: {ix['name_long']}\nLocation: {location}\nMedia Type: {ix['media']}\nSupported Protocol Types: {protocols}\nTech Contact: {tech_contact}\nPolicy Contact: {policy_contact}\nTotal Networks: {ix['net_count']}\nTraffic Stats: {ix['url_stats']}")