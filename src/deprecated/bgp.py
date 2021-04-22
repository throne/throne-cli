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

from requests import request
import click

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
    url = f"https://stat.ripe.net/data/as-overview/data.json?resource={as_number}"
    response = request("GET", url)
    if response.status_code == 200:
        json = response.json()
        asn = json['data']['resource']
        as_block = json['data']['block']['resource']
        block_desc = json['data']['block']['desc']
        block_name = json['data']['block']['name']
        holder = json['data']['holder']
        announced = json['data']['announced']
        click.echo("---Basic ASN Info--")
        click.echo(f"AS#: {asn}\nHolder: {holder}\nAnnounced: {announced}")
        click.echo("---AS Block Info---")
        click.echo(f"AS Block: {as_block}\nName: {block_name}\nDescription: {block_desc}")
        if "ARIN" in block_desc:
            url = f"https://rdap-bootstrap.arin.net/bootstrap/autnum/{as_number}"
            response = request("GET", url)
            if response.status_code == 200:
                json = response.json()
                org_handle = json['entities'][0]['handle']
                org_vcard = json['entities'][0]['vcardArray']
                #org_name = rjson.loads(org_vcard)
                click.echo("---ARIN Information---")
                click.echo(f"Organzation Handle: {org_handle}\nOrganization Name: {org_vcard}")

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
#@click.option('-a', '--address', help='IP Address or Prefix (ex. 1.1.1.1 or 1.0.0.0/24)')
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