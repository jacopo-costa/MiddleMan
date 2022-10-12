from random import randint

import requests
from pyzabbix import ZabbixSender, ZabbixMetric

url = "http://localhost:8080/api_jsonrpc.php"


def login(user, password):
    id = randint(1, 200)

    loginreq = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {
            "user": user,
            "password": password
        },
        "id": id
    }

    return requests.post(url, json=loginreq).json()


def list_hosts(id, auth):
    gethosts = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": [
                "hostid",
                "host",
                "groupid"
            ],
            "selectInterfaces": [
                "interfaceid",
                "ip"
            ]
        },
        "id": id,
        "auth": auth
    }

    return requests.post(url, json=gethosts).json()


def get_host(id, auth, host):
    gethost = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "filter": {
                "host": host
            }
        },
        "id": id,
        "auth": auth
    }

    return requests.post(url, json=gethost).json()


def get_host_groups(id, auth, host):

    gethostgroups = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": ["hostid"],
            "selectHostGroups": "extend",
            "filter": {
                "host": [
                    host
                ]
            }
        },
        "auth": auth,
        "id": id
    }

    return requests.get(url, json=gethostgroups).json()


def get_host_group(id, auth, group):
    gethostgroup = {
        "jsonrpc": "2.0",
        "method": "hostgroup.get",
        "params": {
            "output": "extend",
            "filter": {
                "name": [
                    group
                ]
            }
        },
        "id": id,
        "auth": auth
    }

    return requests.get(url, json=gethostgroup).json()


def add_host_group(id, auth, group):
    addhostgroup = {
        "jsonrpc": "2.0",
        "method": "hostgroup.create",
        "params": {
            "name": group
        },
        "auth": auth,
        "id": id
    }

    return requests.post(url, json=addhostgroup).json()


def add_host(id, auth, host, groupid):
    gethost = {
        "jsonrpc": "2.0",
        "method": "host.create",
        "params": {
            "host": host,
            "groups": [
                {
                    "groupid": groupid
                }
            ]
        },
        "id": id,
        "auth": auth
    }

    return requests.post(url, json=gethost).json()


def add_item(id, auth, hostid, name, key):
    additem = {
        "jsonrpc": "2.0",
        "method": "item.create",
        "params": {
            "name": name,
            "key_": key,
            "hostid": hostid,
            "type": 2,
            "value_type": 4
        },
        "id": id,
        "auth": auth
    }

    return requests.post(url, json=additem).json()


def add_trigger(id, auth, desc, exp):
    addtrigger = {
        "jsonrpc": "2.0",
        "method": "trigger.create",
        "params": [
            {
                "description": desc,
                "expression": exp,
                "priority": 2
            }
        ],
        "id": id,
        "auth": auth
    }

    #'last(/' + host + '/sophos.health)<>"good"'

    return requests.post(url, json=addtrigger).json()


def send_alert(hostname, key, health):
    metrics = []
    m = ZabbixMetric(hostname, key, health)
    metrics.append(m)
    zbx = ZabbixSender('Zabbix')
    zbx.send(metrics)

    return
