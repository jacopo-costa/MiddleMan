import mysql.connector

db = mysql.connector.connect(host="localhost", user="root", password="middlemanpw", database="middleman")

zabbix_url = "http://localhost:8080/api_jsonrpc.php"

sophos_auth = ''
sophos_id = ''
region = ''
zabbix_auth = ''
zabbix_id = ''

token_expired = False
thread_flag = False
