from random import randint

import requests
from pyzabbix import ZabbixSender, ZabbixMetric

import global_vars as gl


def add_host(hostname, groupid):
    gethost = {
        "jsonrpc": "2.0",
        "method": "host.create",
        "params": {
            "host": hostname,
            "groups": [
                {
                    "groupid": groupid
                }
            ]
        },
        "id": gl.zabbix_id,
        "auth": gl.zabbix_auth
    }

    return requests.post(gl.zabbix_url, json=gethost).json()


def add_host_group(groupname):
    addhostgroup = {
        "jsonrpc": "2.0",
        "method": "hostgroup.create",
        "params": {
            "name": groupname
        },
        "id": gl.zabbix_id,
        "auth": gl.zabbix_auth
    }

    return requests.post(gl.zabbix_url, json=addhostgroup).json()


def add_item(hostid, name, key):
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
        "id": gl.zabbix_id,
        "auth": gl.zabbix_auth
    }

    return requests.post(gl.zabbix_url, json=additem).json()


def add_trigger(desc, exp):
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
        "id": gl.zabbix_id,
        "auth": gl.zabbix_auth
    }

    # 'last(/' + host + '/sophos.health)<>"good"'

    return requests.post(gl.zabbix_url, json=addtrigger).json()


def get_host(hostname):
    gethost = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "filter": {
                "host": hostname
            }
        },
        "id": gl.zabbix_id,
        "auth": gl.zabbix_auth
    }

    return requests.post(gl.zabbix_url, json=gethost).json()


def get_host_group(groupname):
    gethostgroup = {
        "jsonrpc": "2.0",
        "method": "hostgroup.get",
        "params": {
            "output": "extend",
            "filter": {
                "name": [
                    groupname
                ]
            }
        },
        "id": gl.zabbix_id,
        "auth": gl.zabbix_auth
    }

    return requests.get(gl.zabbix_url, json=gethostgroup).json()


def get_host_groups(hostname):
    gethostgroups = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": ["hostid"],
            "selectHostGroups": "extend",
            "filter": {
                "host": [
                    hostname
                ]
            }
        },
        "auth": gl.zabbix_auth,
        "id": gl.zabbix_id
    }

    return requests.get(gl.zabbix_url, json=gethostgroups).json()


def get_items(hostid):
    getitems = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": "extend",
            "hostids": hostid
        },
        "id": gl.zabbix_id,
        "auth": gl.zabbix_auth
    }

    return requests.get(gl.zabbix_url, json=getitems).json()


def list_hosts():
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
        "id": gl.zabbix_id,
        "auth": gl.zabbix_auth
    }

    return requests.post(gl.zabbix_url, json=gethosts).json()


def login(user, password):
    zabbix_id = randint(1, 200)

    loginreq = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {
            "user": user,
            "password": password
        },
        "id": zabbix_id
    }

    return requests.post(gl.zabbix_url, json=loginreq).json()


def send_alert(hostname, key, data):
    print("{} {} {}".format(hostname, key, data))
    metrics = []
    m = ZabbixMetric(hostname, key, data)
    metrics.append(m)
    zbx = ZabbixSender('Zabbix')
    zbx.send(metrics)

    return


def update_host_groups(hostid, groups):
    updategroups = {
        "jsonrpc": "2.0",
        "method": "host.update",
        "params": {
            "hostid": hostid,
            "groups": groups
        },
        "id": gl.zabbix_id,
        "auth": gl.zabbix_auth
    }

    return requests.post(gl.zabbix_url, json=updategroups).json()
