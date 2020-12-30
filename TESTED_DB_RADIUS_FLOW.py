#!/usr/bin/python3.8
# -*- coding: UTF-8 -*-

import MySQLdb
import pyshark
# import time
import requests
import datetime
# import pdb
# from log import Log

ip = "10.0.48.43"
ipPort = ip + ":8181"
capture = pyshark.LiveCapture(interface='ens192',bpf_filter='udp port 1812 or udp port 1813',display_filter='radius.code==2 or radius.code==4 or radius.code==5')
#capture_group_user = pyshark.LiveCapture(interface='ens192',bpf_filter='udp port 1812',display_filter='radius.code==2')
# capture.sniff(timeout=5)
# capture
def print_callback(pkt):
    print(pkt.radius.code)

    # 打开数据库连接
    db = MySQLdb.connect(ip, "root", "123sql", "sdn", charset='utf8')
    # 使用cursor()方法获取操作游标
    cursor = db.cursor()

#    if pkt is None or pkt.radius.user_name is None or pkt.radius.framed_ip_address is None or pkt.radius.acct_status_type is None:
    if pkt.radius.code=='2' and hasattr(pkt.radius,'filter_id') and hasattr(pkt.radius,'user_name'):
        print (hasattr(pkt.radius,'filter_id'))
        # dict_user_group[pkt.radius.user_name]=pkt.radius.filter_id
        insertsql="insert into `access_log` (user_name,filter_id)  VALUES('%s','%s') on duplicate key update filter_id = '%s';commit" % (pkt.radius.user_name,pkt.radius.filter_id,pkt.radius.filter_id)
        # insertsql="if not exists (select * from `access_log` where user_name = '%s');INSERT INTO `access_log` (user_name,filter_id) VALUES('%s','%s');else update `access_log` set filter_id = '%s' where user_name = '%s';commit"% (pkt.radius.user_name,pkt.radius.user_name,pkt.radius.filter_id,pkt.radius.filter_id,pkt.radius.user_name)
        print("insertsql====",insertsql)
        cursor.execute(insertsql)

    #计费
    elif pkt.radius.code=='4' and hasattr(pkt.radius,'framed_ip_address') and hasattr(pkt.radius,'acct_status_type'):
        print ("code==4")

        #pdb.set_trace()
        #print (pkt.radius)
        dupsql = "SELECT * FROM `access_log` WHERE (radius_id=" + pkt.radius.id + " AND user_name='" + pkt.radius.user_name + "' AND framed_ip_address='" + pkt.radius.framed_ip_address + "' AND acct_status_type='" + pkt.radius.acct_status_type + "' AND create_date >= '" + str(datetime.datetime.now() - datetime.timedelta(seconds=3)) + "')"
        # print (dupsql)
        cursor.execute(dupsql)
        print ("need new:",cursor.fetchall() == ())
        if cursor.fetchall() == ():
            #pdb.set_trace()
            checksql="SELECT `filter_id` FROM `access_log` WHERE `user_name`='%s';commit" % (pkt.radius.user_name)
            cursor.execute(checksql)
            print ("checksql:",checksql)
            res1 = cursor.fetchall()
            print ("checksql res1:",res1)
            print ("INSERT?:",res1 == ())
            timenow = datetime.datetime.now()
            # acct_status_type=pkt.radius.acct_status_type
            # if pkt.radius.acct_status_type == "3":
            #     acct_status_type="1"
            if res1 == ():
                # log=Log("DongRuan","/home/SDN/pyshark/", pkt.radius.user_name)
                # log.info(str(pkt.radius))
                # insertsql="INSERT INTO `access_log` (`radius_id`, `user_name`, `framed_ip_address`, `filter_id`, `create_date`) VALUES (%s, '%s', '%s', '%s', '%s');commit" % (pkt.radius.id, pkt.radius.user_name, pkt.radius.framed_ip_address, dict_user_group[pkt.radius.user_name],timenow)
                print ("user_name user_group(filter)  name not exisist ERROR")
                return None
            else:
                updatesql="UPDATE `access_log` SET `framed_ip_address`='%s', `create_date`='%s' WHERE `user_name`='%s';commit" % (pkt.radius.framed_ip_address,datetime.datetime.now(),pkt.radius.user_name)
                cursor.execute(updatesql)
            # insradidsql="if not exists (select * from `access_radiusid` where `radius_id` = '%s');INSERT INTO `access_radiusid` (`user_name`,`framed_ip_address`, `filter_id`, `create_date`) VALUES('%s','%s','%s','%s');else update `access_radiusid` set `user_name`='%s',framed_ip_address`='%s',`filter_id` = '%s',``create_date`='%s' where radius_id = '%s';commit"% \
            #             (pkt.radius.id,pkt.radius.user_name,pkt.radius.framed_ip_address,pkt.radius.filter_id,timenow,pkt.radius.user_name,pkt.radius.framed_ip_address,pkt.radius.filter_id,timenow,pkt.radius.id)
                insradidsql="INSERT INTO `access_radiusid` (`radius_id`,`user_name`,`framed_ip_address`, `filter_id`,`create_date`) VALUES('%s','%s','%s','%s','%s') on duplicate key update user_name = '%s',framed_ip_address = '%s',filter_id = '%s',create_date = '%s';commit"% \
                        (pkt.radius.id,pkt.radius.user_name,pkt.radius.framed_ip_address,res1[0][0],timenow,pkt.radius.user_name,pkt.radius.framed_ip_address,res1[0][0],timenow)
            cursor.execute(insradidsql)
        else:
            print("duplicated")



    #计费
    elif pkt.radius.code=='5' and hasattr(pkt.radius,'reply_message'):
        print ("code==5")
        getdusersql="SELECT `user_name`,`framed_ip_address`,`filter_id` FROM `access_radiusid` WHERE `radius_id`='%s' ;commit" % (pkt.radius.id)
        cursor.execute(getdusersql)
        access_radiuses=cursor.fetchall()
        if access_radiuses == ():
            print ("radius_id %s not found in acces_radiusid")
            return None
        else:
            user_name = access_radiuses[0][0]
            print ("5user_name:",user_name)
            framed_ip_address = access_radiuses[0][1]
            print ("5framed_ip_address:",framed_ip_address)
            filter_id = access_radiuses[0][2]
            print ("5filter_id:",filter_id)

            getconfigsql = "SELECT config_name,type,config_ip,subnet FROM service_config LEFT JOIN role_service_binding ON service_config.config_name=role_service_binding.service_name where (role_service_binding.user_role='" + filter_id + "' AND role_service_binding.is_delete='N' AND service_config.is_delete='N');commit"
            #pdb.set_trace()
            cursor.execute(getconfigsql)
            configdatas = cursor.fetchall()
            for index,configdata in enumerate(configdatas):
                flowiden = str(hash(user_name + configdata[0]))
                url = "http://" + ipPort + "/restconf/config/opendaylight-inventory:nodes/node/openflow:147059310694/flow-node-inventory:table/0/flow/" + flowiden
                if configdata[1] == "0":
                    dst_ip_address = configdata[2] + "/32"
                elif configdata[1] == "1":
                    dst_ip_address = configdata[3]
                else:
                    print ("ip type error")
                    return None
                if pkt.radius.reply_message == "acct start ok":
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
                                        "ipv4-source": "' + framed_ip_address + '/32", \n\
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
                    print("response:",response.text.encode('utf8'))
                elif pkt.radius.reply_message == "acct stop ok":
                    payload = {}
                    headers = {
                        'Authorization': 'Basic YWRtaW46YWRtaW4=',
                        'Cookie': 'JSESSIONID=hqf4oljgt7s71svlhzhx2jp4k'
                    }
                    requests.request("DELETE", url, headers=headers, data = payload)
                    print ("deleted")
        #pdb.set_trace()
        checksql="SELECT * FROM `access_log` WHERE `user_name`='%s' AND `filter_id`='%s';commit" % (user_name,filter_id)
        cursor.execute(checksql)
        print ("5checksql:",checksql)
        res1 = cursor.fetchall()
        print ("5checksql res1:",res1)
        print ("5INSERT?:",res1 == ())
        if pkt.radius.reply_message == "acct start ok":
            acct_status_type="1"
        elif pkt.radius.reply_message == "acct stop ok":
            acct_status_type="2"
        else:
            return None
        if res1 == ():
            # log=Log("DongRuan","/home/SDN/pyshark/", pkt.radius.user_name)
            # log.info(str(pkt.radius))
            insertsql="INSERT INTO `access_log` (`acct_status_type`, `create_date`) VALUES ('%s', '%s');commit" % (acct_status_type,datetime.datetime.now())
        else:
            insertsql="UPDATE `access_log` SET `acct_status_type`='%s', `create_date`='%s' WHERE `user_name`='%s';commit" % (acct_status_type,datetime.datetime.now(),user_name)
        cursor.execute(insertsql)
        # if pkt.radius.reply_message == "acct start ok":

    # 关闭数据库连接 never reached
    db.close()
if __name__ == '__main__':
    # dict_user_group={}
    capture.apply_on_packets(print_callback)
