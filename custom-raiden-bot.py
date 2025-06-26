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
        if "веб-угроз" in KES_module:
            message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
                      f"*❗ {data_fileaction}* ❗\n\n" \
                      f"*🔧 Модуль KES:*\n" \
                      f"└ {KES_module}\n\n" \
                      f"*💻 Имя хоста:*\n" \
                      f"└ {data_host}\n\n" \
                      f"*🐱 Пользователь:*\n" \
                      f"└ {KES_p7}\n\n" \
                      f"*🔗 URL:*\n" \
                      f"└ {KES_p5}\n\n" \
                      f"#kaspersky #webthreat \n\n"
        else:
            message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
                      f"*❗ {data_fileaction} ❗*\n\n" \
                      f"*🔧 Модуль KES:*\n" \
                      f"└ {KES_module}\n\n" \
                      f"*💻 Имя хоста:*\n" \
                      f"└ {data_host}\n\n" \
                      f"*🐱 Пользователь:*\n" \
                      f"└ {KES_p7}\n\n" \
                      f"*👾 ID объекта:*\n" \
                      f"└ {KES_p5}\n\n" \
                      f"*📁 Путь к объекту:*\n" \
                      f"└ {data_dstuser}\n\n" \
                      f"#kaspersky #virus \n\n"

    case "100009":
        message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
                  f"*❗ {data_fileaction} ❗*\n\n" \
                  f"*🔧 Модуль KES:*\n\n" \
                  f"└ {KES_module}\n\n" \
                  f"*💻 Имя хоста:*\n" \
                  f"└ {data_host}\n\n" \
                  f"*🐱 Пользователь:*\n" \
                  f"└ {KES_p7}\n\n" \
                  f"*👾 ID объекта:*\n" \
                  f"└ {KES_p5}\n\n" \
                  f"*📁 Путь к объекту:*\n" \
                  f"└ {data_dstuser}\n\n" \
                  f"#kaspersky #virus \n\n"
    case "100011":
        message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
                  f"*❗ {data_fileaction} ❗*\n\n" \
                  f"*🔧 Модуль KES:*\n" \
                  f"└ {KES_module}\n\n" \
                  f"*💻 Имя хоста:*\n" \
                  f"└ {data_host}\n\n" \
                  f"*👾 Тип атаки:*\n" \
                  f"└ {KES_p1}\n\n" \
                  f"*🌍 Src IP:*\n" \
                  f"└ {KES_srcIP}\n\n" \
                  f"*🌏 Dst IP:*\n" \
                  f"└ {KES_dstIP}\n\n" \
                  f"#kaspersky #netattack \n\n"
    case "100012":
        message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
                  f"*❗ {data_fileaction} ❗*\n\n" \
                  f"*🔧 Модуль KES:*\n" \
                  f"└ {KES_module}\n\n" \
                  f"*💻 Имя хоста:*\n" \
                  f"└ {data_host}\n\n" \
                  f"*🐱 Пользователь:*\n" \
                  f"└ {KES_p7}\n\n" \
                  f"*📱 Приложение:* {KES_p6}\n" \
                  f"*└ {KES_p6}\n\n" \
                  f"#kaspersky #maliciousapp \n\n"
    case "100040":
        message = f"*🚨 Kaspersky Alert 🚨*\n\n" \
                  f"*❗ {data_fileaction} ❗*\n\n" \
                  f"*🔧 Модуль KES:*\n" \
                  f"└ {KES_module}\n\n" \
                  f"*💻 Имя хоста:*\n" \
                  f"└ {data_host}\n\n" \
                  f"*🌍 IP источника:*\n" \
                  f"└ {data_dstip}\n\n" \  
                  f"*🔗 URL ресурса:*\n" \
                  f"└ {KES_susURL}\n\n" \ 
                  f"📱 Приложение:* {KES_susEXE}\n" \
                  f"└ {KES_susEXE}\n\n" \
                  f"*📁 Путь к объекту:*\n" \
                  f"└ {KES_susPath}\n\n" \
                  f"#kaspersky #connblocked \n\n"    
    case _:
        pass

# Generate message based on AlertCenter alert group ID
match alert_group_ID:
    case "13":
        message = f"*🚨 AlertCenter Incident 🚨*\n\n" \
                  f"*❗ {alert_name} обнаружено ❗*\n\n" \
                  f"*💻 Имя хоста:*\n" \
                  f"└ {intercept_PCname_caps}\n\n" \
                  f"*📧 Отправитель:*\n" \
                  f"└ {intercept_user} \n\n" \
                  f"*📨 Получатель:*\n" \
                  f"└ {to_addr}\n\n" \
                  f"*📄 Имя документа:*\n" \
                  f"└ {document_name}\n\n" \
                  f"*💠 Расширение:*\n" \
                  f"└ {document_ext}\n\n" \
                  f"*↗️ Размер:*\n" \
                  f"└ {document_size}\n\n" \
                  f"*🆔 ID инцидента:*\n" \
                  f"└ {incident_ID}\n\n" \
                  f"#alertcenter #personalmail \n\n"
    case "15":
        message = f"*🚨 AlertCenter Incident 🚨*\n\n" \
                  f"*❗ {alert_name} обнаружено ❗*\n\n" \
                  f"*💻 Имя хоста:*\n" \
                  f"└ {intercept_PCname_caps}\n\n" \
                  f"*📧 Отправитель:*\n" \
                  f"└ {intercept_user} \n\n" \
                  f"*📨 Получатель:*\n" \
                  f"└ {to_addr}\n\n" \
                  f"*📄 Имя документа:*\n" \
                  f"└ {document_name}\n\n" \
                  f"*💠 Расширение:*\n" \
                  f"└ {document_ext}\n\n" \
                  f"*↗️ Размер:*\n" \
                  f"└ {document_size}\n\n" \
                  f"*🆔 ID инцидента:*\n" \
                  f"└ {incident_ID}\n\n" \
                  f"#alertcenter #personalmail \n\n"
    case "21":
        message = f"*🚨 AlertCenter Incident 🚨*\n\n" \
                  f"*❗ {alert_name} обнаружено ❗*\n\n" \
                  f"*💻 Имя хоста:*\n" \
                  f"└ {intercept_PCname_caps}\n\n" \
                  f"*📧 Отправитель:*\n" \
                  f"└ {intercept_user} \n\n" \
                  f"*📨 Получатель:*\n" \
                  f"└ {to_addr}\n\n" \
                  f"*📄 Имя документа:*\n" \
                  f"└ {document_name}\n\n" \
                  f"*💠 Расширение:*\n" \
                  f"└ {document_ext}\n\n" \
                  f"*↗️ Размер:*\n" \
                  f"└ {document_size}\n\n" \
                  f"*🆔 ID инцидента:*\n" \
                  f"└ {incident_ID}\n\n" \
                  f"#alertcenter #messengers \n\n"
    case "29":
        message = f"*🚨 AlertCenter Incident 🚨*\n\n" \
                  f"*❗ {alert_name} обнаружено ❗*\n\n" \
                  f"*💻 Имя хоста:*\n" \
                  f"└ {intercept_PCname_caps}\n\n" \
                  f"*📧 Отправитель:*\n" \
                  f"└ {intercept_user} \n\n" \
                  f"*📨 Получатель:*\n" \
                  f"└ {to_addr}\n\n" \
                  f"*📄 Имя документа:*\n" \
                  f"└ {document_name}\n\n" \
                  f"*💠 Расширение:*\n" \
                  f"└ {document_ext}\n\n" \
                  f"*↗️ Размер:*\n" \
                  f"└ {document_size}\n\n" \
                  f"*🆔 ID инцидента:*\n" \
                  f"└ {incident_ID}\n\n" \
                  f"#alertcenter #cloud \n\n"
    case "34":
        message = f"*🚨 AlertCenter Incident 🚨*\n\n" \
                  f"*❗ {alert_name} обнаружено ❗*\n\n" \
                  f"*💻 Имя хоста:*\n" \
                  f"└ {intercept_PCname_caps}\n\n" \
                  f"*📧 Отправитель:*\n" \
                  f"└ {intercept_user} \n\n" \
                  f"*📨 Получатель:*\n" \
                  f"└ {to_addr}\n\n" \
                  f"*📄 Имя документа:*\n" \
                  f"└ {document_name}\n\n" \
                  f"*💠 Расширение:*\n" \
                  f"└ {document_ext}\n\n" \
                  f"*↗️ Размер:*\n" \
                  f"└ {document_size}\n\n" \
                  f"*🆔 ID инцидента:*\n" \
                  f"└ {incident_ID}\n\n" \
                  f"#alertcenter #fired \n\n"
    case _:
        pass

# Generate message based on vuln severity
match vuln_severity:
    case 'Critical':
        message = f"*🚨 Critical Vulnerability Alert 🚨*\n\n" \
                  f"*❗ Критическая уязвимость обнаружена на {agent} ❗*\n\n" \
                  f"*#️⃣ CVE:*\n" \
                  f"└ {vuln_CVE}\n\n" \
                  f"*🔧 Уязвимый модуль:*\n" \
                  f"└ {vuln_package} {vuln_version}\n\n" \
                  f"*📄 Описание:*\n" \
                  f"└ {vuln_title}\n\n" \
                  f"*📑 Подробнее:*\n" \
                  f"└ {vuln_reference}\n\n" \
                  f"#vulnerability #critical \n\n"
    case 'High':
        message = f"*🚨 Critical Vulnerability Alert 🚨*\n\n" \
                  f"*❗ Критическая уязвимость обнаружена на {agent} ❗*\n\n" \
                  f"*#️⃣ CVE:*\n" \
                  f"└ {vuln_CVE}\n\n" \
                  f"*🔧 Уязвимый модуль:*\n" \
                  f"└ {vuln_package} {vuln_version}\n\n" \
                  f"*📄 Описание:*\n" \
                  f"└ {vuln_title}\n\n" \
                  f"*📑 Подробнее:*\n" \
                  f"└ {vuln_reference}\n\n" \
                  f"#vulnerability #high \n\n"
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
