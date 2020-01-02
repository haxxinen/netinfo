#!/usr/bin/env python

"""
Shows network IPs and routes.

Usage:
    netinfo gateway
    netinfo ip_local
    netinfo ip_external
    netinfo ip_tor
    netinfo ip_tor <proxy_ip>
    netinfo dns_reverse
    netinfo hostname
    netinfo hostname <ip_address>
    netinfo ip_of <hostname>
    netinfo external_scan <port>
    netinfo traceroute
    netinfo geoip
    netinfo geoip <ip_address>

Options:
    gateway       Show default gateway and interface.
    ip_local      Show local IP address on default interface.
    ip_external   Show external IP address.
    ip_tor        Show TOR IP address (default is localhost).
    dns_reverse   Show reverse DNS record on external IP.
    hostname      Hostname of local/remote machine.
    ip_of         Show IP address of hostname.
    external_scan Scan port on external IP address.
    traceroute    Get traceroute from external service to internal.
    geoip         Get GeoIP info (default is external IP address).
"""

import netifaces
import re
import socket
import json
import ipaddress
import requests
from docopt import docopt


def default_gateway():
    return netifaces.gateways()['default'][netifaces.AF_INET]


def request(url, proxies=None):
    return requests.get(url, proxies=proxies, timeout=10).text.strip('\n')


def proxy_request(url, scheme, proxy_host, proxy_port):
    proxy = scheme + '://' + proxy_host + ':' + str(proxy_port)
    return request(url, {'http': proxy, 'https': proxy})


def trigger():
    if arguments['gateway']:
        gateway, interface = default_gateway()
        print('Gateway: ' + gateway)
        print('Interface: ' + interface)

    if arguments['ip_local']:
        gateway, interface = default_gateway()
        print(netifaces.ifaddresses(interface)[netifaces.AF_INET][-1]['addr'])

    if arguments['ip_external']:
        try:
            print(request('https://ipv4.icanhazip.com'))
            print(request('https://ipv6.icanhazip.com'))
        except:
            pass

    if arguments['ip_tor']:
        proxy_host = arguments['<proxy_ip>']
        proxy_port = 9050
        scheme = 'socks5'
        url = 'https://icanhazip.com'

        try:
            print(proxy_request(url, scheme, 'localhost' if proxy_host is None else proxy_host, proxy_port))
        except requests.exceptions.ConnectionError:
            print('Proxy connection error.')
        except ValueError:
            print('Not a valid proxy.')

    if arguments['dns_reverse']:
        print(request('https://icanhazptr.com'))

    if arguments['hostname']:
        ip = arguments['<ip_address>']

        if ip is None:
            print(socket.gethostname())
            exit(0)

        try:
            ipaddress.ip_address(str(ip))
            name, alias, addresslist = socket.gethostbyaddr(ip)
            print(name)
        except socket.error:
            print('Unknown host.')
        except ValueError:
            print('Not a valid IP address.')

    if arguments['ip_of']:
        hostname = arguments['<hostname>']
        try:
            list = socket.getaddrinfo(hostname, 80, 0, 0, socket.IPPROTO_TCP)
            for i in list:
                print(i[-1][0])
        except socket.error:
            print('Unknown host.')

    if arguments['external_scan']:
        port = arguments['<port>']
        error = 'Invalid port number.'

        try:
            port = int(port)
        except ValueError:
            print(error)

        if not 0 <= int(port) <= 65535:
            raise ValueError(error)

        try:
            r = requests.post('http://canyouseeme.org', data={'port': port})
            if len(r.text) is not 0:
                print('Not open.' if not re.search('Success', r.text) else 'Open.')

        except requests.ConnectionError or requests.ConnectTimeout:
            print('CanYouSeemMe.org is down...')

    if arguments['traceroute']:
        print(re.sub('.* \*' + chr(0x0a), '', request('https://icanhaztraceroute.com')))

    if arguments['geoip']:

        ip = arguments['<ip_address>']
        ip = ip if ip is not None else request('https://icanhazip.com')

        try:
            ipaddress.ip_address(str(ip))
        except ValueError:
            print('Not a valid IP address.')
            exit(0)

        obj = json.loads(request('https://www.maxmind.com/geoip/v2.1/city/' + ip + '?demo=1'))
        if 'error' in obj:
            print(obj['error'])
            exit(0)

        traits = obj['traits']

        if 'is_anonymous_proxy' in traits:
            print('Anonymous proxy.')
            exit(0)

        city = obj['city'] if 'city' in obj else None
        country = obj['country']
        continent = obj['continent']

        print('City: ' + city['names']['en'] if city is not None and 'names' in city else 'City: unknown')
        print('Country: ' + country['iso_code'] + ' (' + continent['code'] + ')')
        print('ISP: ' + traits['isp'] + ' (' + (traits['domain'] if 'domain' in traits else 'unknown') + ')')
        print('IP: ' + ip)


if __name__ == '__main__':
    try:
        arguments = docopt(__doc__)
        trigger()

    except KeyboardInterrupt:
        exit('')
    except EOFError:
        exit('')
