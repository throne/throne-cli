# throne-cli

[![Master Branch Testing](https://github.com/throne/throne-cli/actions/workflows/master-push.yml/badge.svg?branch=master)](https://github.com/throne/throne-cli/actions/workflows/master-push.yml) [![Development Branch Testing](https://github.com/throne/throne-cli/actions/workflows/dev-push.yml/badge.svg?branch=devel)](https://github.com/throne/throne-cli/actions/workflows/dev-push.yml)

[Read the full docs here!](https://www.throne.dev/docs/introduction)

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