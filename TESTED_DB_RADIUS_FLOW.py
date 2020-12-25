#!/usr/bin/python3.8
# -*- coding: UTF-8 -*-

import MySQLdb
import pyshark
import time
import requests
import datetime
import pdb

ip = "10.0.48.43"
ipPort = ip + ":8181"
capture = pyshark.LiveCapture(interface='ens192',bpf_filter='udp port 1812 or udp port 1813',display_filter='radius.code==2 or radius.code==4')
#capture_group_user = pyshark.LiveCapture(interface='ens192',bpf_filter='udp port 1812',display_filter='radius.code==2')
# capture.sniff(timeout=5)
# capture
def group_user_callback(pkt):
    print(pkt.radius)
    if pkt is None or pkt.radius.user_name is None or pkt.radius.filter_id is None:
        print ("some thing None pkt user_name or filter_id")
    else:
        dict_user_group[pkt.radius.user_name]=pkt.radius.filter_id
def print_callback(pkt):
    print(pkt.radius.code)
#    if pkt is None or pkt.radius.user_name is None or pkt.radius.framed_ip_address is None or pkt.radius.acct_status_type is None:
    if pkt.radius.code=='2' and hasattr(pkt.radius,'filter_id') and hasattr(pkt.radius,'user_name'):
        print (hasattr(pkt.radius,'filter_id'))
        dict_user_group[pkt.radius.user_name]=pkt.radius.filter_id
    elif pkt.radius.code=='4' and pkt.radius.user_name in dict_user_group and hasattr(pkt.radius,'framed_ip_address'):
        print ("code==4")
        # 打开数据库连接
        db = MySQLdb.connect(ip, "root", "123sql", "sdn", charset='utf8')
        # 使用cursor()方法获取操作游标
        cursor = db.cursor()
        #pdb.set_trace()
        #print (pkt.radius)
        dupsql = "SELECT * FROM `access_log` WHERE (radius_id=" + pkt.radius.id + " AND user_name='" + pkt.radius.user_name + "' AND framed_ip_address='" + pkt.radius.framed_ip_address + "' AND filter_id='" + dict_user_group[pkt.radius.user_name] + "' AND acct_status_type='" + pkt.radius.acct_status_type + "' AND create_date >= '" + str(datetime.datetime.now() - datetime.timedelta(seconds=3)) + "')"
        print (dupsql)
        cursor.execute(dupsql)
        if cursor.fetchall() == ():
            getconfigsql = "SELECT config_name,type,config_ip,subnet FROM service_config LEFT JOIN role_service_binding ON service_config.config_name=role_service_binding.service_name where (role_service_binding.user_role='" + dict_user_group[pkt.radius.user_name] + "' AND role_service_binding.is_delete='N' AND service_config.is_delete='N');commit"
            #pdb.set_trace()		
            cursor.execute(getconfigsql)
            configdatas = cursor.fetchall()
            for index,configdata in enumerate(configdatas):
                flowiden = pkt.radius.user_name + pkt.radius.framed_ip_address + str(index)
                url = "http://" + ipPort + "/restconf/config/opendaylight-inventory:nodes/node/openflow:147059310694/flow-node-inventory:table/0/flow/" + flowiden
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
                    payload = '{ \n\
                        "flow-node-inventory:flow": [ \n\
                            { \n\
                                "table_id": 0, \n\
                                "id": "' + flowiden + '", \n\
                                "match": { \n\
                                    "ipv4-source": "' + pkt.radius.framed_ip_address + '/32", \n\
                                    "ipv4-destination": "' + dst_ip_address + '" \n\
                                }, \n\
                                "instructions": { \n\
                                    "instruction": [ \n\
                                        { \n\
                                            "order": 20, \n\
                                            "apply-actions": { \n\
                                                "action": [ \n\
                                                    { \n\
                                                        "order": 1, \n\
                                                        "output-action": { \n\
                                                            "output-node-connector": "11" \n\
                                                        } \n\
                                                    } \n\
                                                ] \n\
                                            } \n\
                                        } \n\
                                    ] \n\
                                }, \n\
                                "cookie": 1024, \n\
                                "priority": 110, \n\
                                "hard-timeout": 0, \n\
                                "idle-timeout": 1800 \n\
                            } \n\
                        ] \n\
                    }'
                    response = requests.request("PUT", url, headers=headers, data = payload)
                    print("url:",url)
                    print("payload:",payload)
                    print("pesponse:",response.text.encode('utf8'))
                elif pkt.radius.acct_status_type == "2":
                    payload = {}
                    headers = {
                        'Authorization': 'Basic YWRtaW46YWRtaW4=',
                        'Cookie': 'JSESSIONID=hqf4oljgt7s71svlhzhx2jp4k'
                    }
                    requests.request("DELETE", url, headers=headers, data = payload)
                    print ("deleted")
            #pdb.set_trace()
            insertsql="INSERT INTO `access_log` (`radius_id`, `user_name`, `framed_ip_address`, `filter_id`, `acct_status_type`, `create_date`) VALUES (%s, '%s', '%s', '%s', '%s', '%s');commit" % (pkt.radius.id, pkt.radius.user_name, pkt.radius.framed_ip_address, dict_user_group[pkt.radius.user_name],pkt.radius.acct_status_type,datetime.datetime.now())
            cursor.execute(insertsql)
        else:
            print ("request duplicated")

        # 关闭数据库连接
        db.close()
if __name__ == '__main__':
    dict_user_group={}
    capture.apply_on_packets(print_callback)
