#!/usr/bin/env python

import sys
import json
import requests
from requests.auth import HTTPBasicAuth

# CHAT_ID is your Telegram chat ID (group or personal), starts with -
CHAT_ID="-<YOUR_CHAT_ID>"  

# Read configuration parameters
alert_file = open(sys.argv[1])
hook_url = sys.argv[3]

# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

### Generic data fields section ###
alert_level = alert_json['rule']['level'] if 'level' in alert_json['rule'] else "N/A"
description = alert_json['rule']['description'] if 'description' in alert_json['rule'] else "N/A"
rule_id = alert_json['rule']['id'] if 'id' in alert_json['rule'] else "N/A"
agent = alert_json['agent']['name'] if 'name' in alert_json['agent'] else "N/A"
agent_ip = alert_json['agent']['ip'] if 'ip' in alert_json['agent'] else "N/A"
src_ip = alert_json.get('data', {}).get('srcip', "N/A")
system_message = alert_json.get('data', {}).get('win', {}).get('eventdata', {}).get('memberName', "N/A")
subject_user_name = alert_json.get('data', {}).get('win', {}).get('eventdata', {}).get('subjectUserName', "N/A")
event_id = alert_json.get('data', {}).get('win', {}).get('system', {}).get('eventID', "N/A")

# KES variable section
data_host = alert_json.get('data', {}).get('host', "N/A")
KES_module = alert_json.get('data', {}).get('KES', {}).get('module', "N/A")
KES_p1 = alert_json.get('data', {}).get('KES', {}).get('p1', "N/A")
KES_p2 = alert_json.get('data', {}).get('KES', {}).get('p2', "N/A")
KES_p3 = alert_json.get('data', {}).get('KES', {}).get('p3', "N/A")
KES_p4 = alert_json.get('data', {}).get('KES', {}).get('p4', "N/A")
KES_p5 = alert_json.get('data', {}).get('KES', {}).get('p5', "N/A")
KES_p6 = alert_json.get('data', {}).get('KES', {}).get('p6', "N/A")
KES_p7 = alert_json.get('data', {}).get('KES', {}).get('p7', "N/A")
KES_p8 = alert_json.get('data', {}).get('KES', {}).get('p8', "N/A")
KES_srcIP = alert_json.get('data', {}).get('KES', {}).get('srcIP', "N/A")
KES_dstIP = alert_json.get('data', {}).get('KES', {}).get('dstIP', "N/A")
KES_susURL = alert_json.get('data', {}).get('KES', {}).get('susURL', "N/A")
KES_susPath = alert_json.get('data', {}).get('KES', {}).get('susPath', "N/A")
KES_susEXE = alert_json.get('data', {}).get('KES', {}).get('susEXE', "N/A")
data_dstip = alert_json.get('data', {}).get('dstip', "N/A")
data_dstuser = alert_json.get('data', {}).get('dstuser', "N/A")
data_fileaction = alert_json.get('data', {}).get('fileaction', "N/A")

# AlertCenter variable section
alert_ID = alert_json.get('data', {}).get('AlertID', "N/A")
alert_group_ID = alert_json.get('data', {}).get('AlertGroupID', "N/A")
alert_name = alert_json.get('data', {}).get('AlertName', "N/A")
intercept_user = alert_json.get('data', {}).get('InterceptUser', "N/A")
incident_ID = alert_json.get('data', {}).get('IncidentID', "N/A")
intercept_IP = alert_json.get('data', {}).get('InterceptIP', "N/A")
intercept_PCname = alert_json.get('data', {}).get('InterceptPCName', "N/A")
document_name = alert_json.get('data', {}).get('DocumentName', "N/A")
document_ext = alert_json.get('data', {}).get('DocumentExt', "N/A")
document_size = alert_json.get('data', {}).get('DocumentSize', "N/A")
to_addr = alert_json.get('data', {}).get('to_addr', "N/A")

# Vulnerabilities variable section
vuln_CVE = alert_json.get('data', {}).get('vulnerability', {}).get('CVE', "N/A")
vuln_package = alert_json.get('data', {}).get('vulnerability', {}).get('package', {}).get('name', "N/A")
vuln_version = alert_json.get('data', {}).get('vulnerability', {}).get('package', {}).get('version', "N/A")
vuln_reference = alert_json.get('data', {}).get('vulnerability', {}).get('reference', "N/A")
vuln_severity = alert_json.get('data', {}).get('vulnerability', {}).get('severity', "N/A")
vuln_title = alert_json.get('data', {}).get('vulnerability', {}).get('title', "N/A")

# Generate message based on KES rule ID
match rule_id:
    case "100003":
        message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
                  f"*{data_fileaction}*\n\n" \
                  f"*Модуль KES:* {KES_module}\n\n" \
                  f"*Имя хоста:* {data_host}\n\n" \
                  f"*Пользователь:* {KES_p7}\n\n" \
                  f"*ID объекта:* {KES_p5}\n\n" \
                  f"*Путь к объекту:* {data_dstuser}\n\n" 
    case "100009":
        message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
                  f"*{data_fileaction}*\n\n" \
                  f"*Модуль KES:* {KES_module}\n\n" \
                  f"*Имя хоста:* {data_host}\n\n" \
                  f"*Пользователь:* {KES_p7}\n\n" \
                  f"*ID объекта:* {KES_p5}\n\n" \
                  f"*Путь к объекту:* {data_dstuser}\n\n"
    case "100011":
        message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
                  f"*{data_fileaction}*\n\n" \
                  f"*Модуль KES:* {KES_module}\n\n" \
                  f"*Имя хоста:* {data_host}\n\n" \
                  f"*Тип атаки:* {KES_p1}\n\n" \
                  f"*Src IP:* {KES_srcIP}\n\n" \
                  f"*Dst IP:* {KES_dstIP}\n\n" 
    case "100012":
        message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
                  f"*{data_fileaction}*\n\n" \
                  f"*Модуль KES:* {KES_module}\n\n" \
                  f"*Имя хоста:* {data_host}\n\n" \
                  f"*Пользователь:* {data_dstuser}\n\n" \
                  f"*Приложение:* {KES_p6}\n\n" 
    case "100040":
        message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
                  f"*{data_fileaction}*\n\n" \
                  f"*Имя хоста:* {data_host}\n\n" \
                  f"*IP источника:* {data_dstip}\n\n" \
                  f"*URL ресурса:* {KES_susURL}\n\n" \
                  f"*Приложение:* {KES_susEXE}\n\n" \
                  f"*Путь к объекту:* {KES_susPath}\n\n" 
    case _:
        pass

# Generate message based on AlertCenter rule ID
match alert_group_ID:
    case "13":
        message = f"*🚨 AlertCenter Alert 🚨*\n\n" \
                  f"*{alert_name} обнаружено на *{intercept_PCname}\n\n" \
                  f"*Отправитель:* {intercept_user}\n\n" \
                  f"*Получатель:* {to_addr}\n\n" \
                  f"*Имя документа:* {document_name}\n\n" \
                  f"*Расширение:* {document_ext}\n\n" \
                  f"*Размер:* {document_size}\n\n" \
                  f"*ID инцидента:* {incident_ID}\n\n"
    case "15":
        message = f"*🚨 AlertCenter Alert 🚨*\n\n" \
                  f"*{alert_name} обнаружено на *{intercept_PCname}\n\n" \
                  f"*Отправитель:* {intercept_user}\n\n" \
                  f"*Получатель:* {to_addr}\n\n" \
                  f"*Имя документа:* {document_name}\n\n" \
                  f"*Расширение:* {document_ext}\n\n" \
                  f"*Размер:* {document_size}\n\n" \
                  f"*ID инцидента:* {incident_ID}\n\n"
    case "21":
        message = f"*🚨 AlertCenter Alert 🚨*\n\n" \
                  f"*{alert_name} обнаружено на *{intercept_PCname}\n\n" \
                  f"*Отправитель:* {intercept_user}\n\n" \
                  f"*Получатель:* {to_addr}\n\n" \
                  f"*Имя документа:* {document_name}\n\n" \
                  f"*Расширение:* {document_ext}\n\n" \
                  f"*Размер:* {document_size}\n\n" \
                  f"*ID инцидента:* {incident_ID}\n\n"
    case "29":
        message = f"*🚨 AlertCenter Alert 🚨*\n\n" \
                  f"*{alert_name} обнаружено на *{intercept_PCname}\n\n" \
                  f"*Отправитель:* {intercept_user}\n\n" \
                  f"*Получатель:* {to_addr}\n\n" \
                  f"*Имя документа:* {document_name}\n\n" \
                  f"*Расширение:* {document_ext}\n\n" \
                  f"*Размер:* {document_size}\n\n" \
                  f"*ID инцидента:* {incident_ID}\n\n"
    case _:
        pass

# Generate message based on vuln severity
match vuln_severity:
    case 'Critical':
        message = f"*🚨 Critical Vulnerability Alert 🚨*\n\n" \
                  f"*Критическая уязвимость обнаружена на *{agent}\n\n" \
                  f"*CVE:* {vuln_CVE}\n\n" \
                  f"*Уязвимый модуль:* {vuln_package} {vuln_version}\n\n" \
                  f"*Описание:* {vuln_title}\n\n" \
                  f"*Подробнее:* {vuln_reference}\n\n" 
    case 'High':
        message = f"*🚨 High Vulnerability Alert 🚨*\n\n" \
                  f"*Уязвимость высокой степени обнаружена на *{agent}\n\n" \
                  f"*CVE:* {vuln_CVE}\n\n" \
                  f"*Уязвимый модуль:* {vuln_package} {vuln_version}\n\n" \
                  f"*Описание:* {vuln_title}\n\n" \
                  f"*Подробнее:* {vuln_reference}\n\n"
    case _:
        pass

# Generate request data
msg_data = {
    'chat_id': CHAT_ID,
    'text': message,
    'parse_mode': 'Markdown'  # Using Markdown formatting
}
 
headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

# Send the request
requests.post(hook_url, headers=headers, data=json.dumps(msg_data))
 
sys.exit(0)
