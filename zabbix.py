import json
from functools import wraps
from random import randint

import requests
from flask import request, jsonify, Blueprint
from pyzabbix import ZabbixSender, ZabbixMetric

url = "http://Zabbix-Front:8080/api_jsonrpc.php"
user = 'Admin'
password = 'cavolfiore2022'

zabbix = Blueprint('zabbix', __name__)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        id = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if 'x-request-id' in request.headers:
            id = request.headers['x-request-id']

        if not token or not id:
            return jsonify({'message': 'Token or ID is missing!'}), 401

        current_user = {
            "id": id,
            "auth": token
        }

        return f(current_user, *args, **kwargs)

    return decorator


@zabbix.route("/zabbix/login", methods=['GET'])
def zabbix_login():
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

    res = requests.post(url, json=loginreq).json()
    return jsonify(message="Login executed",
                   code=200,
                   token=res['result'],
                   id=res['id'])


@zabbix.route("/zabbix/gethosts", methods=['GET'])
@token_required
def list_hosts(current_user):
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
        "id": current_user['id'],
        "auth": current_user['auth']
    }

    return requests.post(url, json=gethosts).json()


@zabbix.route("/zabbix/gethost", methods=['GET'])
@token_required
def get_host(current_user):
    list = json.loads(request.json)

    gethost = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "filter": {
                "host": list
            }
        },
        "id": current_user['id'],
        "auth": current_user['auth']
    }

    return requests.post(url, json=gethost).json()


@zabbix.route("/zabbix/gethostgroup/<groupname>", methods=['GET'])
@token_required
def get_host_group(current_user, groupname):
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
        "id": current_user['id'],
        "auth": current_user['auth']
    }

    return requests.get(url, json=gethostgroup).json()


@zabbix.route("/zabbix/addhost", methods=['POST'])
@token_required
def add_host(current_user):
    host = request.args.get('host')
    groupid = request.args.get('groupid')

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
        "id": current_user['id'],
        "auth": current_user['auth']
    }

    return requests.post(url, json=gethost).json()


@zabbix.route("/zabbix/additem", methods=['POST'])
@token_required
def add_item(current_user):
    hostid = request.args.get('hostid')
    name = request.args.get('name')
    key = request.args.get('key')

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
        "id": current_user['id'],
        "auth": current_user['auth']
    }

    return requests.post(url, json=additem).json()


@zabbix.route("/zabbix/addtrigger/<host>", methods=['POST'])
@token_required
def add_trigger(current_user, host):
    addtrigger = {
        "jsonrpc": "2.0",
        "method": "trigger.create",
        "params": [
            {
                "description": "Sophos detected an anomaly",
                "expression": 'last(/' + host + '/sophos.health)<>"good"',
                "priority": 4
            }
        ],
        "id": current_user['id'],
        "auth": current_user['auth']
    }

    return requests.post(url, json=addtrigger).json()


@zabbix.route("/zabbix/sendalert", methods=['POST'])
@token_required
def send_alert(current_user):
    alert = request.json
    print(alert)

    metrics = []
    m = ZabbixMetric(alert['hostname'], 'sophos.health', alert['health'])
    metrics.append(m)
    zbx = ZabbixSender('172.20.0.3')
    zbx.send(metrics)

    return jsonify(message="Alert sent",
                   code=200)
