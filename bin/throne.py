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

# Import Modules
import logging
import click
from src.bgp import bgp
from src.peeringdb import pdb
from src.ip import ip

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