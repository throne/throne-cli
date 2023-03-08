import os
import time
from click.testing import CliRunner
from bin.throne import cli as throne

runner = CliRunner()

shodan_key = os.environ['SHODAN_KEY']
throne_user = os.environ['THRONE_USER']
throne_pass = os.environ['THRONE_PASS']

def test_throne_setapi():
    print("Testing: throne api set")
    response = runner.invoke(throne, ["api", "set", "-u", throne_user, "-p", throne_pass])
    #if "Successfully" in response.output:
    #    test = True
    #else:
    #    test = False
    #assert test == True
    print(response.output)

def test_shodan_setapi():
    print("Testing: throne shodan setapi")
    response = runner.invoke(throne, ["shodan", "setapi"], input=f"{shodan_key}")
    if "Successfully" in response.output:
        test = True
    else:
        test = False
    assert test == True