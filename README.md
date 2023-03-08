# throne-cli

[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://forthebadge.com) 

[![PyPI](https://img.shields.io/pypi/v/throne?color=gold&label=throne)](https://www.throne.dev) ![Maintenance](https://img.shields.io/maintenance/yes/2023) ![GitHub](https://img.shields.io/github/license/throne/throne-cli)

![GitHub Workflow Status (branch)](https://img.shields.io/github/actions/workflow/status/throne/throne-cli/master-push.yml?branch=master
) ![GitHub Workflow Status (branch)](https://img.shields.io/github/actions/workflow/status/throne/throne-cli/dev-push.yml?branch=devel)

______

 [![codecov](https://codecov.io/gh/throne/throne-cli/branch/master/graph/badge.svg?token=V4VPD1SMET)](https://codecov.io/gh/throne/throne-cli)

## [Read the full docs here!](https://www.throne.dev/docs/introduction)

---

## What is throne?
**throne** is an open-source command line tool developed by a network engineer for network engineers. thrones purpose is to help make looking up
internet related information easier on the person doing it. 

Ever needed to look up who owns an IP? Need to check a BGP looking glass to see if your prefix is getting advertised? What about getting abuse contacts? 
I've needed to do that and I've always had to go to multiple sites to get all of the information. throne fixes that. throne leverages APIs from 
multiple different sources and presents the information you're looking for in one easy to use place in a readable format.

## Features

- Gathers RIR information on a specified AS#
- Gets RIR information on IP prefixes or IP addresses (v4 & v6)
- BGP looking glass queries
- IP Geolocation queries
- PeeringDB queries (Only providing organization by ASN & IX information currently)

## APIs Leveraged

- [ARIN RDAP](https://www.arin.net/resources/registry/whois/rdap/)
- [RIPEstat](https://stat.ripe.net/docs/data_api)
- [PeeringDB](https://www.peeringdb.com/apidocs/)
- [ip-api](https://ip-api.com/)
- [Shodan](https://developer.shodan.io/api/introduction)
- [IANA RDAP](https://www.iana.org/help/rdap-requirements)
- [throne API](https://www.throne.dev/docs/throne-api)