# netinfo
Get your network IPs and routes.

This is a small script that shows infomation about your (default) IP addresses in use, network gateway, geoip and more.

## Setup

##### 1. Fetch dependencies on local `virtualenv`
```console
$ sudo apt-get install python3-pip
$ sudo pip3 install virtualenv
$ git clone https://github.com/haxxinen/netinfo && mv netinfo .netinfo && cd .netinfo
$ virtualenv -p python3 .venv
$ . .venv/bin/activate
(.venv) netinfo$ pip3 install -r requirements.txt && deactivate
```

##### 2. Link project as alias
```console
~/.netinfo$ py="`pwd`/.venv/bin/python"
~/.netinfo$ netinfo="`pwd`/netinfo.py"
$ echo >> ~/.bash_profile
$ echo '### netinfo' >> ~/.bash_profile
$ echo "alias netinfo='$py $netinfo'" >> ~/.bash_profile
```

##### 3. Restart `bash` session to apply changes


## Usage

##### 1. Help menu
```console
$ netinfo --help
Get your network IPs and routes.

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
```

##### 2. In action
```console
$ netinfo gateway
Gateway: 192.168.1.1
Interface: en1
$ netinfo ip_of github.com
192.30.253.113
192.30.253.112
$ netinfo hostname 8.8.8.8
google-public-dns-a.google.com
```
