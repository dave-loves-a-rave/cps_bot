#!/usr/bin/env python3

import os
import re
from time import sleep
import math
import pudb

def getSysName(ip, user, auth_pw, priv_pw):
    """ Fetches the system name being parsed """
    response = os.popen('snmpget -v3 -u {} -A {} -l authPriv -a SHA -x AES -X {} {} SNMPv2-MIB::sysName.0 2>/dev/null'.format(user, auth_pw, priv_pw, ip)).read()
    response = response.split()[3]
    return response

def getTable(ip, user, auth_pw, priv_pw):
    """ Fetches CPS table from the specified device and returns a multi-line string. """
    response = os.popen('snmptable -Pe -v3 -u {} -A {} -l authPriv -a SHA -x AES -X {} {} PAN-COMMON-MIB::panZoneTable 2>/dev/null'.format(user, auth_pw, priv_pw, ip)).read()
    response = response.split('\n')
    return response

def getZones(in_string):
    """Parses response for zones on the firewall. Returns a list of the zones."""
    z_list = []
    for line in in_string:
        if "Type" in line:
            line = line.strip(' ')
            line = line[:line.find('Wrong')]
            line = line.strip(' ')
            z_list.append(line)
    return z_list

def loadData(sysName, zone):
    """Loads sample data for a given zone and returns it in a dictionary."""
    sample_dict = {'tcp':[], 'udp':[], 'other':[]}
    prot_list = ['tcp', 'udp', 'other']
    for protocol in prot_list:
        infile = open('./{}/{}/{}_{}_sample.log'.format(sysName, zone, zone, protocol), 'r+')
        for line in infile:
            line = line.strip('\n')
            sample_dict[protocol].append(line)
    return sample_dict

def findPeak(samples):
    """Finds highest sample in the list of samples passed in."""
    high = 0
    for sample in samples:
        if int(sample) > high:
            high = int(sample)
    return high

def findMean(samples):
    """Finds and returns the mean of the samples passed in."""
    sum = 0
    for sample in samples:
        sum += int(sample)
    avg = sum/len(samples)
    return avg

def findSD(samples):
    """Finds and returns the mean and standard deviation for the set of samples passed in."""
    mean = findMean(samples)
    diff_list = []
    for sample in samples:
        diff = int(sample) - int(mean)
        diff = diff ** 2
        diff_list.append(diff)
    diff_avg = findMean(diff_list)
    sd = math.sqrt(diff_avg)
    return sd

def main():
    read_user = ''
    read_auth_pw = ''
    read_priv_pw = ''
    fw_ip = input("What firewall would you like to poll? ")
    read_user_input = input("Enter the snmp user for the firewall -> ")
    read_auth_pw_input = input("Enter the snmp auth password for the firewall -> ")
    read_priv_pw_input = input("Enter the snmp priv password for the firewall -> ")
    minutes = input("How many minutes would you like to poll? ")
    poll_num = int(minutes) * 6
    # Check for read string input. If there is no input, use the default
    if read_user_input:
        read_user = read_user_input
    if read_auth_pw_input:
        read_auth_pw = read_auth_pw_input
    if read_priv_pw_input:
        read_priv_pw = read_priv_pw_input
    # Regex for matching
    match_unsigned = re.compile('Unsigned32')
    match_gauge = re.compile('Gauge32')
    match_count = re.compile('([0-9]+)')
    # Get list of zones
    zone_data = getTable(fw_ip, read_user, read_auth_pw, read_priv_pw)
    zone_list = getZones(zone_data)
    # Create subdirectories for zone samples
    sysName = getSysName(fw_ip, read_user, read_auth_pw, read_priv_pw)
    for zone in zone_list:
        os.system('mkdir -p ./{}/"{}"'.format(sysName, zone))
    # Initialize poll counter
    poll_count = 0
    # pudb.set_trace()
    # Gather data points
    while poll_count < poll_num:
        this_resp = getTable(fw_ip, read_user, read_auth_pw, read_priv_pw)
        for line in this_resp:
            if "Type" in line:
                zone = line.strip(' ')
                zone = zone[:zone.find('Wrong')]
                zone = zone.strip(' ')
                line = line[line.find('Wrong'):]
                line = re.sub(match_unsigned, 'p', line)
                line = re.sub(match_gauge, 'p', line)
                cps = match_count.findall(line)
                if cps is not None:
                    tcp_outfile = open('./{}/{}/{}_tcp_sample.log'.format(sysName, zone, zone), 'a')
                    udp_outfile = open('./{}/{}/{}_udp_sample.log'.format(sysName, zone, zone), 'a')
                    other_outfile = open('./{}/{}/{}_other_sample.log'.format(sysName, zone, zone), 'a')
                    tcp_outfile.write(str(cps[0]) + '\n')
                    udp_outfile.write(str(cps[1]) + '\n')
                    other_outfile.write(str(cps[2]) + '\n')
                    tcp_outfile.close()
                    udp_outfile.close()
                    other_outfile.close()
        poll_count += 1
        sleep(10)
    summary_outfile = open('./{}/summary.txt'.format(sysName), 'w')
    # Calculate suggested thresholds
    prot_list = ['tcp', 'udp', 'other']
    for zone in zone_list:
        zone_data_dict = loadData(sysName, zone)
        summary_outfile.write('{}/{}\n'.format(sysName, zone))
        for protocol in prot_list:
            peak = findPeak(zone_data_dict[protocol])
            mean = findMean(zone_data_dict[protocol])
            sd = findSD(zone_data_dict[protocol])
            alert = int(mean) + int(sd)
            activate = 1.1 * int(peak)
            maximum = 1.1 * 1.1 * int(peak)
            summary_outfile.write('\n'
                                  '\t{}\n'
                                  '\t\tAlert Threshold: \t{}\n'
                                  '\t\tActivate Threshhold: \t{}\n'
                                  '\t\tMax Threshold:\t\t{}\n\n'.format(protocol, alert, activate, maximum))
        summary_outfile.write("==================================================================\n\n")
    summary_outfile.close()
    print("Analysis Complete!!")

if __name__ == "__main__":
    main()
