import os
import time
from click.testing import CliRunner
from bin.throne import cli as throne

runner = CliRunner()

shodan_key = os.environ['SHODAN_KEY']
#throne_user = os.environ['THRONE_USER']
#throne_pass = os.environ['THRONE_PASS']
throne_user = "testuser@throne.dev"
throne_pass = "VlWaurxSX3mWAFctaSWH"
def test_throne_setapi():
    print("Testing: throne api set")
    response = runner.invoke(throne, ["api", "set", "-u", throne_user, "-p", throne_pass])
    assert response.exit_code == 0
    assert "Successfully set throne API key." in response.output

def test_shodan_setapi():
    print("Testing: throne shodan setapi")
    response = runner.invoke(throne, ["shodan", "setapi"], input=f"{shodan_key}")
    assert response.exit_code == 0
    assert "Successfully set Shodan API key." in response.output