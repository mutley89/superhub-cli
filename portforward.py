import collections
import re
import urllib.request
import urllib.parse

from bs4 import BeautifulSoup

protocols = {"4": "TCP", "3": "UDP", "254": "TCP+UDP"}

path = "/VmRgPortForwarding.html"
post_path = "/cgi-bin/ForwardingCgi"

class PortForwardError(Exception):
    pass

def portforward(opts):
    url = opts.router_address + path
    res = urllib.request.urlopen(url)
    soup = BeautifulSoup(res.read())
    rule_list = get_rules(soup)
    opts.pf_command(rule_list, soup, opts)
    if opts.pf_command is not list_rules:
        send_rules(rule_list, soup, opts)

def get_rules(soup):
    """
    returns a list of OrderedDicts containing the rules
    """
    # The router sends 20 groups of 7 <input type=hidden> elements, containing
    # the currently set rules. It expects the names and values these back as 
    # form data after any modifications have been made. It always sends and
    # expects 20 goups regardless of how many rules are set. Unset rules have a
    # name of ""
    rule_list = []
    for i in range(20):
        rule = collections.OrderedDict()
        for key in (
                "Name", "StartPort", "EndPort", "Protocol", "IpAddr",
                "Enable", "Delete"):
            elem = soup.find("input", attrs = {
                    "name":"VmPortForwardingRule" + key + str(i)})
            rule[key] = elem["value"]
        rule_list.append(rule)
    return rule_list

def send_rules(rule_list, soup, opts):
    data = collections.OrderedDict()
    for i, rule in enumerate(rule_list):
        for key in rule:
            data["VmPortForwardingRule" + key + str(i)] = rule[key]

    # The same div that contains the rule <input> elements, contains another
    # hidden <input> with a random id as the name attribute. The server
    # expects this back as the name, with a value of 0, as part of the POST
    # request. Neither the <div> nor the <input> have any id or identifying
    # attributes, so just find a rule, then get the last <input> sibling.
    a_rule = soup.find("input", attrs={"name": "VmPortForwardingRuleName1"})
    data[a_rule.find_next_siblings("input")[-1]["name"]] = "0"
    # Other data sent by the web client. Server sends no response whatsover if
    # this isn't sent.
    data["VmPortForwardingRestore"] = "0"

    url = opts.router_address + post_path
    data = urllib.parse.urlencode(data).encode("utf-8")
    headers = {"Content-Type":"application/x-www-form-urlencoded"}
    req = urllib.request.Request(url, data, headers=headers)
    res = urllib.request.urlopen(req)
    return res

def list_rules(rule_list, soup, opts):
    row = "{:15} {:11} {:15} {:8} {:7}"
    print(row.format("Name", "Ports", "IP Address", "Protocol", "Enabled"))
    for rule in rule_list:
        if rule["Name"] != "":
            if rule["StartPort"] == rule["EndPort"]:
                ports = rule["StartPort"]
            else:
                ports = "-".join(rule["StartPort"], rule["EndPort"])
            gateway = re.search(
                    r'^var gatewayIP = "([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)" ;',
                    soup.text, re.M).group(1)
            ip = gateway.split(".")
            ip[3] = rule["IpAddr"]
            ip = ".".join(ip)
            protocol = protocols[rule["Protocol"]]
            enabled = "yes" if rule["Enable"] == "1" else "no"
            print(row.format(
                    rule["Name"], ports, ip, protocol, enabled))

def add_rule(rule_list, soup, opts):
    if opts.name is None:
        # Set default rule name
        opts.name = protocols[opts.protocol] + ":" + opts.ports[0]
        if opts.ports[0] != opts.ports[1]:
            opts.name += "-" + opts.ports[1]
    # Check rule name doesn't already exist and any ports are not already
    # forwarded
    for rule in rule_list:
        if rule["Name"].lower() == opts.name.lower():
            raise PortForwardError(
                    "Rule with name %s already exists" % opts.name)
        if (rule["Protocol"] == "254" or opts.protocol == "254"
                or rule["Protocol"] == opts.protocol == "254"):
            if rule["Name"] != "":
                # Need to check if router allows non enabled rules to overlap.
                # The web interface js doesn't allow this, so do the same for
                # now
                is_forwarded = False
                if (int(opts.ports[0]) <= int(rule["StartPort"]) and
                        int(opts.ports[1]) >= int(rule["EndPort"])):
                    is_forwarded = True
                for port in opts.ports:
                    if (int(port) >= int(rule["StartPort"]) and
                            int(port) <= int(rule["EndPort"])):
                        is_forwarded = True
                if is_forwarded:
                    raise PortForwardError("Port already forwarded")
    # TODO: need to check address and gateway
    gateway = re.search(
            r'^var gatewayIP = "([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)" ;',
            soup.text, re.M).group(1)
    # Router doesn't allow the subnet to be anything other than a /24
    if gateway.split(".")[:3] != opts.address.split(".")[:3]:
        raise PortForwardError("Address must be on same subnet as gateway")
    if opts.address == gateway:
        raise PortForwardError("Address can not be gateway address")
    # find first empty rule
    for rule in rule_list:
        if rule["Name"] == "":
            break
    rule["Name"] = opts.name
    rule["StartPort"] = opts.ports[0]
    rule["EndPort"] = opts.ports[1]
    rule["IpAddr"] = opts.address
    rule["Protocol"] = opts.protocol
    rule["Enable"] = "1"

def delete_rule(rule_list, soup, opts):
    for rule in rule_list:
        if rule["Name"] == opts.name:
            rule["Delete"] = "1"
            break
    else:
        raise PortForwardError("Rule with name %s doesn't exist" % opts.name)

def enable_rule(rule_list, soup, opts):
    for rule in rule_list:
        if rule["Name"] == opts.name:
            rule["Enable"] = "1"
            break
    else:
        raise PortForwardError("Rule with name %s doesn't exist" % opts.name)

def disable_rule(rule_list, soup, opts):
    for rule in rule_list:
        if rule["Name"] == opts.name:
            rule["Enable"] = "0"
            break
    else:
        raise PortForwardError("Rule with name %s doesn't exist" % opts.name)
