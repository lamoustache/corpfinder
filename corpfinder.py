#!/usr/bin/python
#
# -*- coding: utf-8 -*-

import netaddr
import re
import socket
import sys
import getopt

ARIN = "whois.arin.net"
RIPE = "whois.ripe.net"
LACNIC = "whois.lacnic.net"
APNIC = "whois.apnic.net"
AFRINIC = "whois.afrinic.net"

def usage(status=0):
    print "Usage: corpfinder <search> [-h]"
    print "     -s <search>     specify the search term"
    print "     -h              help"
    print
    sys.exit(status)
    
def convert_ip_range_to_cidr(ip_range):
    ip_block = []
    for ip in ip_range:
        ip_start, ip_end = ip.replace(' ', '').split('-')
        cidr = netaddr.iprange_to_cidrs(ip_start, ip_end)
        for i in cidr:
            ip_block.append(i)
    return ip_block
    
def lookup_primary_ripe(hostname, search):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, 43))
    q = "-r " + search + "\r\n"
    s.send(q)
    response = ""
    while True:
        d = s.recv(4096)
        response += d
        if not d:
            break
    s.close()
    
    if "access denied" in response:
        print "Access denied: daily limit passed or host permanently denied"
    else:
        return response 
    
def lookup_primary_arin(hostname, search):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, 43))
    q = ". z " + search + "* \r\n"
    s.send(q)
    response = ""
    while True:
        d = s.recv(4096)
        response += d
        if not d:
            break
    s.close()
    return response
    
def inverse_lookup_ripe(hostname, search, flag):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, 43))
    q = "-r -i " + flag + " " + search + "\r\n"
    s.send(q)
    response = ""
    while True:
        d = s.recv(4096)
        response += d
        if not d:
            break
    s.close()
    return response
    
def inverse_lookup_query_arin():
    pass

def parse_ripe(response):
    records = []
    r_inetnum = re.compile(r'inetnum:\s+(.*)')
    r_netname = re.compile(r'netname:\s+(.*)', re.M)
    r_country = re.compile(r'country:\s+(.*)')
    
    inetnum_range = r_inetnum.findall(response)
    inetnum = convert_ip_range_to_cidr(inetnum_range)
    netname = r_netname.findall(response)
    country = r_country.findall(response)
    
    for i, n, c in zip(inetnum, netname, country):
        data = {'inetnum': i, 'netname': n.upper(), 'country': c.upper()}
        records.append(data)        
    if records:
        return records

def parse_arin(response):
    records = []
    r_result = re.compile(r'(\w+.*)(\(NET.*\))\s(.*)', re.M)
    result = r_result.findall(response)
    for r in result:
        ip = [r[2]]
        cidr = convert_ip_range_to_cidr(ip)
        data = {'netname': r[0].upper(), 'inetnum': cidr[0]}
        records.append(data)
    if records:
        return records

def parse_lookup_ripe(response, search):
    records = []
    r_inetnum = re.compile(r'inetnum:\s+(.*)')
    r_netname = re.compile(r'netname:\s+(.*)', re.M)
    r_descr = re.compile(r'netname:\s+.*\ndescr:\s+(.*)', re.IGNORECASE)
    r_country = re.compile(r'country:\s+(.*)')
    
    inetnum_range = r_inetnum.findall(response)
    inetnum = convert_ip_range_to_cidr(inetnum_range)
    netname = r_netname.findall(response)
    descr = r_descr.findall(response)
    country = r_country.findall(response)
    
    for i, n, d, c in zip(inetnum, netname, descr, country):
        data = {'inetnum': i, 'netname': n.upper(), 'descr': d.upper(), 'country': c.upper()}
        records.append(data)
    if records:
        return records
    
def get_reverse_lookup_key(response, search):
    #r_flag = re.compile('mnt-\w+:\s+(.*'+search+'.*)', re.IGNORECASE)
    r_flag = re.compile('mnt-\w+:\s+(.*)', re.IGNORECASE)
    lookup_key = r_flag.findall(response)
    lookup_key = sorted(set(lookup_key))
    return lookup_key

WHOIS_SERVERS = [RIPE, ARIN, APNIC, AFRINIC]
WHOIS_FLAGS = ['mb', 'mu', 'ml', 'mz', 'md']
SEARCH_Q = ""
  
#search_q = sys.argv[1].upper()

opts = getopt.getopt(sys.argv[1:], "s:h")
for opt,optarg in opts[0]:
    if opt == "-s":
        SEARCH_Q = optarg.upper()
    elif optarg == "-h":
        usage()

if not SEARCH_Q:
    print "\nError: search term not defined\n"
    usage()
  
# Query WHOIS servers.
for hostname in WHOIS_SERVERS:
    # RIPE whois server
    if hostname == RIPE or hostname == APNIC or hostname == AFRINIC:
        print 
        print "[ Query sent to " +hostname+ " ]\n"
        # Get response from RIPE using primary lookup query.
        response = lookup_primary_ripe(hostname, SEARCH_Q)
        if response:
            # Parse response with RIPE parser and print result.
            record = parse_ripe(response)
            if record:
                for rec in record:
                    print rec['inetnum'], rec['netname']
                # Search possible inverse lookup key
                lookup_key = get_reverse_lookup_key(response, SEARCH_Q)
                # Use lookup up keys in inverse queries
                if lookup_key:
                    for lkey in lookup_key:
                        #print "Inverse lookup key: ", lkey
                        for flag in WHOIS_FLAGS:
                            rresponse = inverse_lookup_ripe(hostname, lkey, flag)
                            #print "RRESPONSE", rresponse
                            rrecord = parse_lookup_ripe(rresponse, SEARCH_Q)
                            #print "RRECORD", rrecord
                            if rrecord:
                                for rec in rrecord:
                                    if (SEARCH_Q in rec['descr']) or (SEARCH_Q in rec['netname']):
                                        print rec['inetnum'], rec['descr']
            else:
                print "No records found"
                
    # ARIN whois server 
    if hostname == ARIN:
        print 
        print "[ Query sent to " +hostname+ " ]\n"
        # Get response from ARIN using primary lookup query.
        response = lookup_primary_arin(hostname, SEARCH_Q)
        if response:
            # Parse response with ARIN parser.
            record = parse_arin(response)
            if record:
                for rec in record:
                    print rec['inetnum'], rec['netname']
            else:
                print "No records found"