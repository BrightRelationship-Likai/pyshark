#!/usr/bin/python3.8
# -*- coding: UTF-8 -*-

import MySQLdb
import pyshark
import time
import requests
import datetime
import pdb

ipPort = "10.0.48.33:8181"
capture = pyshark.LiveCapture(interface='ens192',bpf_filter='udp port 1813')
# capture.sniff(timeout=5)
# capture
def print_callback(pkt):
    print (pkt.radius)
    if pkt is None or pkt.radius.user_name is None or pkt.radius.framed_ip_address is None or pkt.radius.acct_status_type is None:
        print ("some thingi pkt user_name or ip_address or status_type None")
    else:
        # 打开数据库连接
        db = MySQLdb.connect("10.0.48.33", "root", "123sql", "sdn", charset='utf8')
        # 使用cursor()方法获取操作游标
        cursor = db.cursor()
        #pdb.set_trace()
        dupsql = "SELECT * FROM `access_log` WHERE (radius_id=" + pkt.radius.id + " AND user_name='" + pkt.radius.user_name + "' AND framed_ip_address='" + pkt.radius.framed_ip_address + "' AND filter_id='" + pkt.radius.filter_id + "' AND acct_status_type='" + pkt.radius.acct_status_type + "' AND create_date >= '" + str(datetime.datetime.now() - datetime.timedelta(seconds=3)) + "')"
        cursor.execute(dupsql)
        if cursor.fetchall() == ():
            getconfigsql = "SELECT config_name,type,config_ip,subnet FROM service_config LEFT JOIN role_service_binding ON service_config.config_name=role_service_binding.service_name where (role_service_binding.user_role='" + pkt.radius.filter_id + "' AND role_service_binding.is_delete='N' AND service_config.is_delete='N');commit"
            #pdb.set_trace()		
            cursor.execute(getconfigsql)
            configdatas = cursor.fetchall()
            for index,configdata in enumerate(configdatas):
                flowiden = pkt.radius.user_name + pkt.radius.framed_ip_address + str(index)
                url = "http://" + ipPort + "/restconf/config/opendaylight-inventory:nodes/node/openflow:147058199337/flow-node-inventory:table/0/flow/" + flowiden
                if configdata[1] == "0":
                    dst_ip_address = configdata[2] + "/32"
                elif configdata[1] == "1":
                    dst_ip_address = configdata[3]
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
                                    \"ipv4-source\": \"" + pkt.radius.framed_ip_address + "/32\", \
                                    \"ipv4-destination\": \"" + dst_ip_address + "\" \
                                }, \
                                \"instructions\": { \
                                    \"instruction\": [ \
                                        { \
                                            \"order\": 20, \
                                            \"apply-actions\": { \
                                                \"action\": [ \
                                                    { \
                                                        \"order\": 1, \
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
            #pdb.set_trace()
            insertsql="INSERT INTO `access_log` (`radius_id`, `user_name`, `framed_ip_address`, `filter_id`, `acct_status_type`, `create_date`) VALUES (%s, '%s', '%s', '%s', '%s', '%s');commit" % (pkt.radius.id, pkt.radius.user_name, pkt.radius.framed_ip_address, pkt.radius.filter_id,pkt.radius.acct_status_type,datetime.datetime.now())
            cursor.execute(insertsql)
        else:
            print ("request duplicated")

        # 关闭数据库连接
        db.close()
    #time.sleep( 1 )
if __name__ == '__main__':
    capture.apply_on_packets(print_callback)
#capture.sniff_continuously(packet_count=10)
