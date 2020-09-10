# BAMF
[![license](https://img.shields.io/badge/license-GNU-brightgreen.svg)](https://github.com/malwaredllc/bamf/LICENSE)
[![version](https://img.shields.io/badge/version-0.1.2-lightgrey.svg)](https://github.com/malwaredllc/bamf)

__DISCLAIMER__: This project should be used for authorized testing and educational purposes only.

BAMF is an open-source tool designed to leverage Shodan (a search engine for the Internet of Things) 
to discover routers vulnerable to [CVE-2013-6026](https://nvd.nist.gov/vuln/detail/CVE-2013-6026), commonly known as *Joel's Backdoor*,
a severe vulnerability allowing unauthenticated access to the administration panel of many routers made by D-Link,
one of the world's largest manufacturers of routers for home and business. 

____________________________________________________________

## Installation

1) Download or clone the repository (`git clone https://github.com/malwaredllc/bamf`)
2) Install the required Python packages (`pip install -r bamf/requirements.txt`)
3) Create a free Shodan account at https://account.shodan.io/register
4) Configure BAMF to use your Shodan API key (`python bamf.py [--shodan API]`)
____________________________________________________________

## Usage

- Use the `search` command to search the internet for potential
- Use the `scan` command to scan the target routers for backdoors
- Use the `map` command to map the networks of devices connected to vulnerable routers
- Use the `targets` command to view potential targets discovered this session
- Use the `backdoors` command to view routers with a confirmed backdoor
- Use the `devices` command to view all devices connected to vulnerable routers


## Contact

__Email__: security@malwared.com

__Twitter__: [![twitter](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/malwaredllc)

