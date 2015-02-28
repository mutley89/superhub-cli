#!/usr/bin/env python3

import argparse
import re
import urllib.request
import urllib.parse
from getpass import getpass

from bs4 import BeautifulSoup

import portforward

#import http.client
#http.client.HTTPConnection.debuglevel = 0

default_router_address = "192.168.0.1" 

class LoginError(Exception):
    pass

def main():
    opts = parse_args()
    login(opts)
    opts.command(opts)
    if opts.logout:
        logout(opts)

def parse_args(cmdline=None):
    parser = argparse.ArgumentParser(description="""CLI interface to the
            Virgin media superhub router""")
    parser.add_argument("-r", "--router-address", type=lambda x: "http://" + x,
            default=default_router_address,
            help="IP address and optional port of router")
    parser.add_argument("-l", "--logout", action="store_true",
            help="Logout when done")
    subparsers = parser.add_subparsers()
    pf_parser = subparsers.add_parser("portforward", aliases=["pf"],
            description="Port forwarding") 
    pf_parser.set_defaults(command=portforward.portforward)
    pf_subparsers = pf_parser.add_subparsers()
    pf_list_parser = pf_subparsers.add_parser("list",
            description="List port forwarding rules")
    pf_list_parser.set_defaults(pf_command=portforward.list_rules)
    pf_add_parser = pf_subparsers.add_parser("add",
            description="Add portforwarding rule")
    def parse_ports(port_string):
        res = port_string.split("-")
        for x in res:
            if not x.isnumeric():
                raise argparse.ArgumentTypeError(
                        "port must be a number, or 2 numbers seperated by -")
            if int(x) < 1 or int(x) > 65535:
                raise argparse.ArgumentTypeError(
                        "Ports must be between 1 and 65535")
        if len(res) == 2:
            if int(res[1]) < int(res[0]):
                raise argparse.ArgumentTypeError(
                        "Start port must not be higher than end port")
        elif len(res) == 1:
            res.append(res[0])
        else:
            raise argparse.ArgumentTypeError(
                    "port must be a number, or 2 numbers seperated by -")
        return res
    pf_add_parser.set_defaults(protocol="254", pf_command=portforward.add_rule)
    pf_add_parser.add_argument("ports", type=parse_ports,
            help="Port to forward. Can be a number or range seperated by -")
    pf_add_parser.add_argument("address",
            help="Internal address to forward port to")
    pf_add_parser.add_argument("--name", help="Name of Rule")
    protocol_group = pf_add_parser.add_mutually_exclusive_group()
    protocol_group.add_argument("--tcp", action="store_const", const="4",
            dest="protocol", help="Forward tcp ports only")
    protocol_group.add_argument("--udp", action="store_const", const="3",
            dest="protocol", help="Forward udp ports only")
    protocol_group.add_argument("--tcp-and-udp", action="store_const",
            const="254", dest="protocol",
            help="Forward both tcp and udp ports")
    pf_delete_parser = pf_subparsers.add_parser("delete", aliases=["del"],
            description="Delete port forward rule")
    pf_delete_parser.set_defaults(pf_command=portforward.delete_rule)
    pf_delete_parser.add_argument("name", help="Name of rule to delete")
    pf_enable_parser = pf_subparsers.add_parser("enable",
            description="Enable port forward rule")
    pf_enable_parser.set_defaults(pf_command=portforward.enable_rule)
    pf_enable_parser.add_argument("name", help="Name of rule to enable")
    pf_disable_parser = pf_subparsers.add_parser("disable",
            description="Disable port forward rule")
    pf_disable_parser.set_defaults(pf_command=portforward.disable_rule)
    pf_disable_parser.add_argument("name", help="Name of rule to disable")
    if cmdline is None:
        return parser.parse_args()
    else:
        return parser.parse_args(cmdline)

# Login seems to be done purely on the basis of ip address, once logged in, no
# cookies or anything else is required to be sent
def login(opts):
    res = urllib.request.urlopen(opts.router_address + "/home.html")
    if res.url == opts.router_address + "/home.html":
        logged_in = True
    else:
        logged_in = False
    password_regex = re.compile('^\tvar res="([^"]*)";', re.M)
    page = res.read()
    while not logged_in:
        soup = BeautifulSoup(page)
        password_name = soup.find("input", id="password")["name"]
        password = getpass()
        url = opts.router_address + "/cgi-bin/VmLoginCgi"
        data = urllib.parse.urlencode({password_name: password}).encode("utf-8")
        headers = {"Content-Type":"application/x-www-form-urlencoded"}
        req = urllib.request.Request(url, data, headers=headers)
        login_res = urllib.request.urlopen(req)
        page = login_res.read()
        page_str = page.decode("iso-8859-1")
        regex_res = password_regex.search(page_str)
        if regex_res.group(1) == "0":
            logged_in = True
        elif regex_res.group(1) == "1":
            print("Incorrect password")
        else:
            raise LoginError

def logout(opts):
    urllib.request.urlopen(opts.router_address + "/VmLogout2.html")

if __name__ == "__main__":
    main()
