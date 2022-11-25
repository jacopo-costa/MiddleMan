"""
random: Use a random int as ID for Zabbix
time: Sleep for the send_alert fun
API: Send request to the Zabbix API
pyzabbix: Use this library to send metrics to Zabbix
"""
from random import randint

import requests
from pyzabbix import ZabbixSender, ZabbixMetric

import config as cfg


def add_host(hostname, groupid, templateid):
    gethost = {
        "jsonrpc": "2.0",
        "method": "host.create",
        "params": {
            "host": hostname,
            "groups": [
                {
                    "groupid": groupid
                }
            ],
            "templates": [
                {
                    "templateid": templateid
                }
            ]
        },
        "id": cfg.zabbix_id,
        "auth": cfg.zabbix_auth
    }

    return requests.post(cfg.url_zabbix, json=gethost).json()


def add_host_group(groupname):
    addhostgroup = {
        "jsonrpc": "2.0",
        "method": "hostgroup.create",
        "params": {
            "name": groupname
        },
        "id": cfg.zabbix_id,
        "auth": cfg.zabbix_auth
    }

    return requests.post(cfg.url_zabbix, json=addhostgroup).json()


def add_item(hostid, name, key):
    # type : 2 == Zabbix trapper
    # value_type : 4 == text
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
        "id": cfg.zabbix_id,
        "auth": cfg.zabbix_auth
    }

    return requests.post(cfg.url_zabbix, json=additem).json()


def add_template(groupid, name):
    template = {
        "jsonrpc": "2.0",
        "method": "template.create",
        "params": {
            "host": name,
            "groups": {
                "groupid": groupid
            }
        },
        "id": cfg.zabbix_id,
        "auth": cfg.zabbix_auth
    }

    return requests.post(cfg.url_zabbix, json=template).json()


def add_template_group(groupname):
    templategroup = {
        "jsonrpc": "2.0",
        "method": "templategroup.create",
        "params": {
            "name": groupname
        },
        "id": cfg.zabbix_id,
        "auth": cfg.zabbix_auth
    }

    return requests.post(cfg.url_zabbix, json=templategroup).json()


def add_trigger(desc, exp, priority):
    addtrigger = {
        "jsonrpc": "2.0",
        "method": "trigger.create",
        "params": [
            {
                "description": desc,
                "expression": exp,
                "priority": priority
            }
        ],
        "id": cfg.zabbix_id,
        "auth": cfg.zabbix_auth
    }

    return requests.post(cfg.url_zabbix, json=addtrigger).json()


def get_host(hostname):
    gethost = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "filter": {
                "host": hostname
            }
        },
        "id": cfg.zabbix_id,
        "auth": cfg.zabbix_auth
    }

    return requests.get(cfg.url_zabbix, json=gethost).json()


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
        "id": cfg.zabbix_id,
        "auth": cfg.zabbix_auth
    }

    return requests.get(cfg.url_zabbix, json=gethostgroup).json()


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
        "auth": cfg.zabbix_auth,
        "id": cfg.zabbix_id
    }

    return requests.get(cfg.url_zabbix, json=gethostgroups).json()


def get_items(hostid):
    getitems = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "output": "extend",
            "hostids": hostid
        },
        "id": cfg.zabbix_id,
        "auth": cfg.zabbix_auth
    }

    return requests.get(cfg.url_zabbix, json=getitems).json()


def get_linked_templates(hostid):
    linkedtemplates = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": ["hostid"],
            "selectParentTemplates": [
                "templateid"
            ],
            "hostids": hostid
        },
        "auth": cfg.zabbix_auth,
        "id": cfg.zabbix_id
    }

    return requests.get(cfg.url_zabbix, json=linkedtemplates).json()


def get_template(name):
    gettemplate = {
        "jsonrpc": "2.0",
        "method": "template.get",
        "params": {
            "output": "extend",
            "filter": {
                "host": [
                    name
                ]
            }
        },
        "id": cfg.zabbix_id,
        "auth": cfg.zabbix_auth
    }

    return requests.get(cfg.url_zabbix, json=gettemplate).json()


def get_template_group(name):
    gettemplategroup = {
        "jsonrpc": "2.0",
        "method": "templategroup.get",
        "params": {
            "output": "extend",
            "filter": {
                "name": [
                    name
                ]
            }
        },
        "id": cfg.zabbix_id,
        "auth": cfg.zabbix_auth
    }

    return requests.get(cfg.url_zabbix, json=gettemplategroup).json()


def list_hosts():
    gethosts = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": [
                "hostid",
                "host",
                "groupid"
            ]
        },
        "id": cfg.zabbix_id,
        "auth": cfg.zabbix_auth
    }

    return requests.get(cfg.url_zabbix, json=gethosts).json()


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

    return requests.post(cfg.url_zabbix, json=loginreq).json()


def send_alert(hostname, key, data):
    # Wait of 0.5 sec for Zabbix to process
    # previous data
    metrics = []
    m = ZabbixMetric(hostname, key, data)
    metrics.append(m)
    zbx = ZabbixSender('Zabbix')
    zbx.send(metrics)


def update_host_groups(hostid, groups):
    updategroups = {
        "jsonrpc": "2.0",
        "method": "host.update",
        "params": {
            "hostid": hostid,
            "groups": groups
        },
        "id": cfg.zabbix_id,
        "auth": cfg.zabbix_auth
    }

    return requests.post(cfg.url_zabbix, json=updategroups).json()


def update_host_templates(hostid, templates):
    updatetemplates = {
        "jsonrpc": "2.0",
        "method": "host.update",
        "params": {
            "hostid": hostid,
            "templates": templates
        },
        "id": cfg.zabbix_id,
        "auth": cfg.zabbix_auth
    }

    return requests.post(cfg.url_zabbix, json=updatetemplates).json()
