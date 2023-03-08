import os
import time
from click.testing import CliRunner
from bin.throne import cli as throne

runner = CliRunner()

shodan_key = os.getenv('SHODAN_KEY')
throne_user = os.getenv('THRONE_USER')
throne_pass = os.getenv('THRONE_PASS')

def test_throne_setapi():
    print("Testing: throne api set")
    print(throne_user)
    response = runner.invoke(throne, ["api", "set", "-u", throne_user, "-p", throne_pass])
    print(response.output)
    assert response.exit_code == 0
    assert "Successfully set throne API key." in response.output

def test_shodan_setapi():
    print("Testing: throne shodan setapi")
    response = runner.invoke(throne, ["shodan", "setapi"], input=f"{shodan_key}")
    assert response.exit_code == 0
    assert "Successfully set Shodan API key." in response.output