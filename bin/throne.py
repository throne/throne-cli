# LICENSED UNDER BSD-3-CLAUSE-CLEAR LICENSE
# SEE PROVIDED LICENSE FILE IN ROOT DIRECTORY

# Import Modules
import logging
import click
from src.bgp import bgp
from src.peeringdb import pdb
from src.ip import ip
from src.shodan import shodan
from src.whois import whois

class Throne:
    def __init__(self):
        self.verbose = False

pass_throne = click.make_pass_decorator(Throne)

@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enables verbose mode.")
@click.pass_context
def cli(ctx, verbose):
    """
    Throne is a command line tool to query various things on the internet.
    """
    if verbose:
        LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
   '[%(funcName)s()] %(message)s')
        logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)

cli.add_command(bgp)
cli.add_command(pdb)
cli.add_command(ip)
cli.add_command(shodan)
cli.add_command(whois)