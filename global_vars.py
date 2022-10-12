import mysql.connector

db = mysql.connector.connect(host="middlesql", user="root", password="middlemanpw", database="middleman")

zabbix_url = "http://Zabbix:8080/api_jsonrpc.php"

sophos_auth = ''
sophos_id = ''
region = ''
zabbix_auth = ''
zabbix_id = ''

token_expired = False
thread_flag = False
