import os
import time
from click.testing import CliRunner
from bin.throne import cli as throne

runner = CliRunner()

def test_ipgeo():
    print("Testing: throne ip geo 1.1.1.1")
    response = runner.invoke(throne, ["ip", "geo", "1.1.1.1"])
    assert response.exit_code == 0
    assert "IP Address: 1.1.1.1" in response.output
    assert "AS Number: AS13335 Cloudflare, Inc." in response.output

def test_ipinfo():
    print("Testing: throne ip info 1.1.1.1")
    response = runner.invoke(throne, ["ip", "info", "1.1.1.1"])
    assert response.exit_code == 0
    assert "RIR: APNIC" in response.output
    assert "---APNIC/CLOUDFLARENET Contact Information---" in response.output

def test_ipinfo_all():
    print("Testing: throne ip info 1.1.1.1 --all")
    response = runner.invoke(throne, ["ip", "info", "1.1.1.1", "--all"])
    assert response.exit_code == 0
    assert "RIR: APNIC" in response.output
    assert "---APNIC/CLOUDFLARENET Contact Information---" in response.output
    assert "---Basic ASN Info--" in response.output
    assert "Holder: CLOUDFLARENET" in response.output
    assert "Cloudflare, Inc. (Registrant)" in response.output
    assert "Entity Email: noc@cloudflare.com" in response.output

def test_bgpasn():
    print("Testing: throne bgp asn 59")
    response = runner.invoke(throne, ["bgp", "asn", "59"])
    assert response.exit_code == 0
    assert "---Basic ASN Info--" in response.output
    assert "Holder: WISC-MADISON-AS" in response.output
    assert "---ARIN/AS59 Contact Information---" in response.output

def test_bgpasn_ripe():
    print("Testing: throne bgp asn 2792")
    response = runner.invoke(throne, ["bgp", "asn", "2792"])
    assert response.exit_code == 0
    assert "---Basic ASN Info--" in response.output
    assert "Holder: TERASTREAM-AS - Deutsche Telekom AG" in response.output
    assert "Some of these details may be filtered by RIPE." in response.output

def test_bgplg_ny():
    print("Testing: throne bgp lg 1.1.1.1 from US-NY")
    response = runner.invoke(throne, ["bgp", "lg", "1.1.1.1", "--location", "US-NY"])
    assert response.exit_code == 0
    assert "Origin AS: 13335" in response.output
    assert "Prefix: 1.1.1.0/24" in response.output

def test_bgplg_de():
    print("Testing: throne bgp lg 1.1.1.1 from DE")
    response = runner.invoke(throne, ["bgp", "lg", "1.1.1.1", "--location", "DE"])
    assert response.exit_code == 0
    assert "Origin AS: 13335" in response.output
    assert "Prefix: 1.1.1.0/24" in response.output

def test_bgplg_za():
    print("Testing: throne bgp lg 1.1.1.1 from ZA")
    response = runner.invoke(throne, ["bgp", "lg", "1.1.1.1", "--location", "ZA"])
    assert response.exit_code == 0
    assert "Origin AS: 13335" in response.output
    assert "Prefix: 1.1.1.0/24" in response.output

def test_bgplg_jp():
    print("Testing: throne bgp lg 1.1.1.1 from JP")
    response = runner.invoke(throne, ["bgp", "lg", "1.1.1.1", "--location", "JP"])
    assert response.exit_code == 0
    assert "Origin AS: 13335" in response.output
    assert "Prefix: 1.1.1.0/24" in response.output

def test_bgpprefix():
    print("Testing: throne bgp prefix 1.1.1.0/24")
    response = runner.invoke(throne, ["bgp", "prefix", "1.1.1.0/24"])
    assert response.exit_code == 0
    assert "Prefix: 1.1.1.0/24" in response.output
    assert "IP Block: 1.0.0.0/8" in response.output
    assert "Status: ALLOCATED" in response.output

def test_pdbasn():
    print("Testing: throne pdb asn 20473")
    response = runner.invoke(throne, ["pdb", "asn", "20473"])
    assert response.exit_code == 0
    assert "---PeeringDB Information---" in response.output
    assert "Id: 1051" in response.output
    assert "Status: ok" in response.output
    assert "Some results may have been ommited due to having no value." in response.output

def test_pdbix_AMSIX():
    print("Testing: throne pdb ix AMS-IX")
    response = runner.invoke(throne, ["pdb", "ix", "AMS-IX"])
    assert response.exit_code == 0
    assert "---PeeringDB Results---" in response.output
    assert "Amsterdam Internet Exchange" in response.output
    assert "Caribbean" in response.output
    assert "Hong Kong" in response.output

def test_pdbix_AMSIX_10():
    print("Testing: throne pdb ix AMS-IX -c 10")
    response = runner.invoke(throne, ["pdb", "ix", "AMS-IX", "-c", "10"])
    assert response.exit_code == 0
    assert "---PeeringDB Results---" in response.output
    assert "Amsterdam Internet Exchange" in response.output
    assert "Caribbean" in response.output
    assert "Hong Kong" in response.output
    assert "San Jose, US" in response.output
    assert "Chicago, US" in response.output
    assert "Mumbai, IN" in response.output

def test_pdbfac_Cologix():
    print("Testing throne pdb fac Cologix")
    response = runner.invoke(throne, ["pdb", "fac", "Cologix"])
    assert response.exit_code == 0
    assert "---PeeringDB Results---" in response.output
    assert "Cologix" in response.output
    assert "Toronto" in response.output
    assert "Minneapolis" in response.output
    assert "Vancouver" in response.output

def test_pdbfac_Cologix_10():
    print("Testing throne pdb fac Cologix -c 10")
    response = runner.invoke(throne, ["pdb", "fac", "Cologix", "-c", "10"])
    assert response.exit_code == 0
    assert "---PeeringDB Results---" in response.output
    assert "Cologix" in response.output
    assert "Toronto" in response.output
    assert "Minneapolis" in response.output
    assert "Vancouver" in response.output
    assert "Montreal" in response.output
    assert "Jacksonville" in response.output

def test_shodan_info():
    print("Testing: throne shodan info")
    response = runner.invoke(throne, ["shodan", "info"])
    assert response.exit_code == 0
    assert "---Shodan API Info---" in response.output
    assert "Total Scan Credits" in response.output
    assert "Total Query Credits" in response.output
    assert "Monitored IP Limit" in response.output

def test_shodan_dns_resolve():
    print("Testing: throne shodan dns cloudflare.com google.com netflix.com reddit.com --query-type resolve")
    response = runner.invoke(throne, ["shodan", "dns", "cloudflare.com", "google.com", "netflix.com", "reddit.com", "--query-type", "resolve"])
    assert response.exit_code == 0
    assert "---Shodan DNS Results---" in response.output
    assert "cloudflare.com resolves to" in response.output
    assert "netflix.com resolves to" in response.output
    assert "google.com resolves to" in response.output
    assert "reddit.com resolves to" in response.output

def test_shodan_dns_reverse():
    print("Testing: throne shodan dns 1.1.1.1 8.8.8.8 208.67.222.222 208.67.220.220 --query-type reverse")
    response = runner.invoke(throne, ["shodan", "dns", "1.1.1.1", "8.8.8.8", "208.67.222.222", "208.67.220.220", "--query-type", "reverse"])
    assert response.exit_code == 0
    assert "---Shodan DNS Results---" in response.output
    assert "208.67.222.222 resolves to" in response.output
    assert "208.67.220.220 resolves to" in response.output
    assert "1.1.1.1 resolves to" in response.output
    assert "8.8.8.8 resolves to" in response.output

def test_shodan_dns_domain():
    print("Testing: throne shodan dns discord.com --query-type domain")
    response = runner.invoke(throne, ["shodan", "dns", "discord.com", "--query-type", "domain"])
    assert response.exit_code == 0
    assert "---Shodan DNS Results---" in response.output
    assert "Domain: discord.com" in response.output
    assert "Shodan Tags:" in response.output
    assert "Subdomains:" in response.output