import os
import time
import yaml
import sys
from click.testing import CliRunner
from bin.throne import cli as throne

runner = CliRunner()

shodan_key = os.environ['SHODAN_KEY']
throne_user = os.environ['THRONE_USER']
throne_pass = os.environ['THRONE_PASS']

def test_throne_setapi():
    print("Testing: throne api set")
    runner.invoke(throne, ["api", "set", "-u", throne_user, "-p", throne_pass])
    #response = runner.invoke(throne, ["api", "set", "-u", throne_user, "-p", throne_pass])
    #if "Successfully" in response.output:
    #    test = True
    #else:
    #    test = False
    #assert test == True
    #print(response.output)

def get_config_output():
    home = os.environ['HOME']
    config_file = f'{home}/.throne/config.yml'
    config = yaml.safe_load(open(config_file))
    print(config)
    sys.stdout.write("This is a test, FIND ME")

def test_shodan_setapi():
    print("Testing: throne shodan setapi")
    response = runner.invoke(throne, ["shodan", "setapi"], input=f"{shodan_key}")
    if "Successfully" in response.output:
        test = True
    else:
        test = False
    assert test == True

test_throne_setapi()
test_shodan_setapi()
get_config_output()