#!/usr/bin/env python2
import argparse
import os
import sys
import pickle
import json
import socket
import struct
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper

SWITCH_TO_HOST1_PORT = 1
SWITCH_TO_HOST2_PORT = 2
SWITCH_TO_HOST3_PORT = 3
TARGET_IP_DEFAULT = "192.168.102.224"
TARGET_PORT_DEFAULT = 9999

def writeTunnelRules(p4info_helper, ingress_sw, dst_eth_addr, dst_ip_addr, mask, egr_port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, mask)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": egr_port
        })
    ingress_sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % ingress_sw.name

def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    table_entries={}
    table_entries['table_entries']=[]
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
	    match = {}
	    for m in entry.match:
                match_name=p4info_helper.get_match_field_name(table_name, m.field_id)
		print match_name,
		match_value=p4info_helper.get_match_field_value(m)
                print '%r' % (p4info_helper.get_match_field_value(m),),
		if 'ip' in match_name:
		    if type(match_value) == tuple:
			match[str(match_name)]=get_ip_from_bytes(match_value[0])
		    else:
		        match[str(match_name)]=get_ip_from_bytes(match_value)
		elif 'dstAaddr' in match_name:
		    match[str(match_name)]=get_mac_from_bytes(match_value)
		else:
		    match[str(match_name)]=match_value
		
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
	    action_params = {}
            for p in action.params:
		action_param_name = p4info_helper.get_action_param_name(action_name, p.param_id)
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
		if 'ip' in action_param_name:
                    if type(match_value) == tuple:
			action_params[str(action_param_name)]=get_ip_from_bytes(p.value[0])
		    else:
			action_params[str(action_param_name)]=get_ip_from_bytes(p.value)
                elif 'dstAddr' in action_param_name:
                    action_params[str(action_param_name)]=get_mac_from_bytes(p.value)
                else:
		    action_params[str(action_param_name)]=p.value
            print
	    table_entries['table_entries'].append({'table': str(table_name), 'match': match, 'action_name': str(action_name), 'action_params': action_params})
    print table_entries
    return table_entries

def get_mac_from_bytes(mac):
    nice_mac = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB",mac)
    return nice_mac

def get_ip_from_bytes(ip):
    nice_ip=socket.inet_ntoa(ip)
    return nice_ip

def send_table_rules(p4info_helper, s1):
    table_rules = readTableRules(p4info_helper, s1)
    table_rules_json = json.dumps(table_rules, encoding = "ISO-8859-1")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(table_rules_json,(TARGET_IP_DEFAULT, TARGET_PORT_DEFAULT))
    sock.close()

def main(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='s1',
        address='127.0.0.1:50051',
        device_id=0,
        proto_dump_file='logs/s1-p4runtime-requests.txt')
    s1.MasterArbitrationUpdate()
    # Install the P4 program on the switch
    s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                   bmv2_json_file_path=bmv2_file_path)
    print "Installed P4 Program using SetForwardingPipelineConfig on s1"
    writeTunnelRules(p4info_helper, ingress_sw=s1, dst_eth_addr="00:00:00:00:01:01", dst_ip_addr="172.16.20.100", mask=32, egr_port=1)
    writeTunnelRules(p4info_helper, ingress_sw=s1, dst_eth_addr="00:00:00:00:01:02", dst_ip_addr="172.16.30.100", mask=32, egr_port=2)
    writeTunnelRules(p4info_helper, ingress_sw=s1, dst_eth_addr="00:00:00:00:01:03", dst_ip_addr="172.16.40.100", mask=30, egr_port=3)
    
    readTableRules(p4info_helper, s1)
    try:
        while True:
            sleep(10)
            print '\n----- Reading table contents ------'
            send_table_rules(p4info_helper, s1)
    except KeyboardInterrupt:
        print " Shutting down."


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)

    main(args.p4info, args.bmv2_json)
