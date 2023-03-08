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

# Set log variable for verbose output
log = logging.getLogger(__name__)

# Get home directory
home = os.environ['HOME']
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
def set(username, password, scope):
    """
    Use this command to login to the throne API and set your API key
    """
    try:
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
    except:
        raise
    try:
        if not os.path.exists(f"{home}/.throne"):
            os.makedirs(f"{home}/.throne")
            Path(f'{home}/.throne/config.yml').touch()
        url = "{0}auth/login".format(THRONE_API)
        if scope is None:
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
                throne_username = {'throne_username': f"{username}"}
                with open(config_file, 'r+') as throne_config:
                    yaml.safe_dump(throne_username, throne_config)
                    yaml.safe_dump(throne_apikey, throne_config)
                click.secho("Successfully set throne API key.", fg="green")
    except:
        raise

@api.command()
def get():
    """
    Use this command to get your username to the throne API.
    """
    try:
        config = yaml.safe_load(open(config_file))
        username = config['throne_username']
        if username != "":
            print(username)
        else:
            print("No username is set.")
    except FileNotFoundError:
        print("A config file could not be found. Please run throne api set to create it.")
    except:
        raise