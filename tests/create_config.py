import os
import time
from click.testing import CliRunner
from bin.throne import cli as throne

runner = CliRunner()

shodan_key = os.getenv('SHODAN_KEY')

def test_shodan_setapi():
    print("Testing: throne shodan setapi")
    response = runner.invoke(throne, ["shodan", "setapi"], input=f"{shodan_key}")
    assert response.exit_code == 0
    assert "Successfully set Shodan API key." in response.output