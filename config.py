"""
Global variables file.
Used to store login tokens for the session, URLs and
the status flags
"""

region = ""
sophos_auth = ""
sophos_id = ""

thread_flag = False
token_expired = False

zabbix_auth = ""
zabbix_id = ""

url_sophos_login = "https://id.sophos.com/api/v2/oauth2/token"
url_sophos_whoami = "https://api.central.sophos.com/whoami/v1"
url_zabbix = ""

# Use this as name for the groups and templates it creates
tenant_name = ""
