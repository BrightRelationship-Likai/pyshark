#!/usr/bin/python3.6
# -*- coding: UTF-8 -*-

import pyshark
import time
import requests

ipPort = "10.0.48.43:8181"
capture = pyshark.LiveCapture(interface='dclient',bpf_filter='udp port 37008')
# capture.sniff(timeout=5)
# capture
def print_callback(pkt):
    if pkt is None or pkt.radius.user_name is None or pkt.radius.framed_ip_address is None or pkt.radius.acct_status_type is None:
        print ("some thingi pkt user_name or ip_address or status_type None")
    else:
        flowiden = pkt.radius.user_name + pkt.radius.framed_ip_address
        url = "http://" + ipPort + "/restconf/config/opendaylight-inventory:nodes/node/openflow:147058199337/flow-node-inventory:table/0/flow/" + flowiden
        if pkt.radius.acct_status_type == "1":
            print (flowiden)

            headers = {
                'Authorization': 'Basic YWRtaW46YWRtaW4=',
                'Content-Type': 'application/json',
                'Cookie': 'JSESSIONID=i3wwhy6l01q71f0g2xr6a2qiq'
            }
            payload = "{ \
                \"flow-node-inventory:flow\": [ \
                    { \
                        \"table_id\": 0, \
                        \"id\": \"" + flowiden + "\", \
                        \"match\": { \
                            \"ipv4-source\": \"" + pkt.radius.framed_ip_address + "/32\" \
                        }, \
                        \"instructions\": { \
                            \"instruction\": [ \
                                { \
                                    \"order\": 20, \
                                    \"apply-actions\": { \
                                        \"action\": [ \
                                            { \
                                                \"order\": 1, \
                                                \"set-field\": { \
                                                    \"vlan-match\": { \
                                                        \"vlan-id\": { \
                                                            \"vlan-id\": 64, \
                                                            \"vlan-id-present\": true \
                                                        } \
                                                    } \
                                                } \
                                            }, \
                                            { \
                                                \"order\": 2, \
                                                \"output-action\": { \
                                                    \"output-node-connector\": \"11\" \
                                                } \
                                            } \
                                        ] \
                                    } \
                                } \
                            ] \
                        }, \
                        \"cookie\": 1024, \
                        \"priority\": 110, \
                        \"hard-timeout\": 0, \
                        \"idle-timeout\": 1800 \
                    } \
                ] \
            }"

            response = requests.request("PUT", url, headers=headers, data = payload)
            print("add flow sended to controller")
            print(response.text.encode('utf8'))
        elif pkt.radius.acct_status_type == "2":
            payload = {}
            headers = {
                'Authorization': 'Basic YWRtaW46YWRtaW4=',
                'Cookie': 'JSESSIONID=hqf4oljgt7s71svlhzhx2jp4k'
            }
            requests.request("DELETE", url, headers=headers, data = payload)
            print ("deleted")
    time.sleep( 3 )
if __name__ == '__main__':
    capture.apply_on_packets(print_callback)
#capture.sniff_continuously(packet_count=10)
