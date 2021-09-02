# LICENSED UNDER BSD-3-CLAUSE-CLEAR LICENSE
# SEE PROVIDED LICENSE FILE IN ROOT DIRECTORY

# Import Third Party Modules
import logging
import click
import yaml
import os
from requests import request
from pathlib import Path
from getpass import getpass
# Import Throne Modules
from src.parsers import json_request, shodan_parser
from src.exceptions import (ThroneParsingError, ThroneFormattingError, ThroneLookupFailed, ThroneHTTPError, ThroneConfigError)

# Set log variable for verbose output
log = logging.getLogger(__name__)

# Get home directory
home = os.path.expanduser("~")
config_file = f'{home}/.throne/config.yml'

try:
    config = yaml.safe_load(open(config_file))
    throne_apikey = config['throne_key']
except:
    pass

# URLS
THRONE_API = 'https://api.throne.dev/'

@click.group()
def api():
    """
    Retrieve API keys from the throne API
    """
    pass

@click.option('--username', '-u', default=None, help="[OPTIONAL] Sets username")
@click.option('--password', '-p', default=None, help="[OPTIONAL] Sets password")
@click.option('--scope', '-s', default=None, help="[OPTIONAL] Sets scope")
@api.command()
def setapi(username, password, scope):
    """
    Use this command to login to the throne API and set your API key
    """
    if username is None:
        username = input("Username: ")
        password = getpass("Password: ")
        set_scope = input("Do you wish to set a scope? (Y/N): ")
        if set_scope == "y" or set_scope == "Y":
            scope = input("Scope: ")
        elif set_scope == "n" or set_scope == "N":
            scope = None
        else:
            print("Invalid Option. Please select Y or N.")
            exit()
    try:
        if not os.path.exists(f"{home}/.throne"):
            os.makedirs(f"{home}/.throne")
            Path(f'{home}/.throne/config.yml').touch()
        url = "{0}auth/login".format(THRONE_API)
        if scope == None:
            payload = f"username={username}&password={password}"
        else:
            payload = f"username={username}&password={password}&scope={scope}"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        response = request("POST", url, headers=headers, data=payload)
        json = response.json()
        for k in json.items():
            if "error" in k:
                click.secho(f"Unable to authenticate. Error: {json['error']} - Reason: {json['error_description']}", fg="red")
            if "access_token" in k:
                throne_apikey = {'throne_key': f"Bearer {json['access_token']}"}
                with open(config_file, 'r+') as throne_config:
                    if os.stat(config_file).st_size == 0:
                        yaml.safe_dump(throne_apikey, throne_config)
                    else:
                        config = yaml.safe_load(throne_config)
                        config.update(throne_apikey)
                        yaml.safe_dump(throne_apikey, throne_config)
                click.secho("Successfully set throne API key.", fg="green")
    except:
        raise