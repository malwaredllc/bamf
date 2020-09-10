![logo](https://malwared.com/wp-content/uploads/2018/08/bamf_logo-02.png)
# BAMF (Backdoor Access Machine Farmer)
[![license](https://img.shields.io/badge/license-GNU-brightgreen.svg)](https://github.com/malwaredllc/bamf/LICENSE)
[![version](https://img.shields.io/badge/version-0.1.2-lightgrey.svg)](https://github.com/malwaredllc/bamf)

__DISCLAIMER__: This project should be used for authorized testing and educational purposes only.

BAMF is an open-source tool designed to leverage Shodan (a search engine for the Internet of Things) 
to discover vulnerable routers, then utilize detected backdoors/vulnerabilities to remotely access 
the router administration panel and modify the DNS server settings.

Changing the primary DNS server of a router hijacks the domain name resolution process, enabling an
attacker to target every device on the network simultaneously to spread malware with drive-by downloads
and harvest credentials via malicious redirects to fraudulent phishing sites.

Currently the only vulnerability detected and exploited is [CVE-2013-6026](https://nvd.nist.gov/vuln/detail/CVE-2013-6026), commonly known as *Joel's Backdoor*,
a severe vulnerability allowing unauthenticated access to the administration panel of many routers made by D-Link,
one of the world's largest manufacturers of routers for home and business. 

This project is still under development and will soon have a more modular design, making it easier
for other developers to add detection & exploitation features for other vulnerabilities.
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

____________________________________________________________

## To Do

*Contributors welcome!Feel free to issue pull-requests with any new features or improvements you have come up with!*

1) Look into using an online vulnerability database API to enable cross-referencing responses from
the Shodan IoT search engine with signatures of backdoors/vulnerabilities
2) Change to modular design to make it easier for other developers to add detection & exploitation features for
 other vulnerabilities
3) Integrate BAMF into the [BYOB](https://github.com/malwaredllc/byob) framework as a distribution mechanism to maximize spreading potential
____________________________________________________________

## Contact

__Website__: https://malwared.com

__Email__: security@malwared.com

__Twitter__: [![twitter](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/malwaredllc)

