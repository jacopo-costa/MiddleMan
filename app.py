from functools import wraps

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

from sophos import sophos
from zabbix import zabbix

app = Flask(__name__)
app.register_blueprint(zabbix)
app.register_blueprint(sophos)
CORS(app)


def credentials_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        sophosauth = None
        sophosID = None
        zabbixauth = None
        zabbixID = None
        region_url = None

        if 'Authorization' in request.headers:
            sophosauth = request.headers['Authorization']

        if 'X-Tenant-ID' in request.headers:
            sophosID = request.headers['X-Tenant-ID']

        if 'X-Region' in request.headers:
            region_url = request.headers['X-Region']

        if 'x-access-token' in request.headers:
            zabbixauth = request.headers['x-access-token']

        if 'x-request-id' in request.headers:
            zabbixID = request.headers['x-request-id']

        if not sophosauth:
            return jsonify({'message': 'Missing Sophos Token'}), 401
        elif not sophosID:
            return jsonify({'message': 'Missing Tenant ID'}), 401
        elif not region_url:
            return jsonify({'message': 'Missing Region data'}), 401

        if not zabbixauth or not zabbixID:
            return jsonify({'message': 'Zabbix Token or ID is missing!'}), 401

        current_user = {
            "sophosauth": sophosauth,
            "sophosID": sophosID,
            "data_region": region_url,
            "zabbixauth": zabbixauth,
            "zabbixID": zabbixID
        }

        return f(current_user, *args, **kwargs)

    return decorator


# Filter hostnames from Sophos endpoints call
def get_sophos_hostnames(endpoints):
    hostnames = []
    for key in endpoints['items']:
        hostnames.append(str(key['hostname']))
    return hostnames


# Filter hostnames from Zabbix get hosts call
def get_zabbix_hostnames(zabbix_hosts):
    hostnames = []
    for key in zabbix_hosts['result']:
        hostnames.append(str(key['host']))
    return hostnames


# Check if hostname is present in both systems (Zabbix & Sophos)
# If not add to a list to return
def find_missing(zabbix_list, sophos_list):
    notpresent = []

    for item in sophos_list:
        if zabbix_list.__contains__(item):
            pass
        else:
            notpresent.append(item)

    return notpresent


# Filter hostnames from Sophos endpoints call
def check_sophos_health(endpoints):
    health_check = []

    for key in endpoints['items']:
        if str(key['health']['overall']) != 'good':
            health_check.append({
                "hostname": str(key['hostname']),
                "health": str(key['health']['overall'])
            })

    return health_check


@app.route("/checkhosts")
@credentials_required
def check_hosts(current_user):
    sophos_endpoints = get_sophos_hostnames(requests.get("http://localhost:5000/sophos/getendpoints",
                                                         headers={
                                                             "Authorization": current_user['sophosauth'],
                                                             "X-Tenant-ID": current_user['sophosID'],
                                                             "X-Region": current_user['data_region']
                                                         }).json())

    zabbix_hosts = get_zabbix_hostnames(requests.get("http://localhost:5000/zabbix/gethosts", headers={
        "x-access-token": current_user['zabbixauth'],
        "x-request-id": current_user['zabbixID']
    }).json())

    notpresent = find_missing(zabbix_hosts, sophos_endpoints)
    print(notpresent)

    if len(notpresent) != 0:
        for x in notpresent:
            # Add the missing host
            newhostid = requests.post("http://localhost:5000/zabbix/addhost", data=x, headers={
                "x-access-token": current_user['zabbixauth'],
                "x-request-id": current_user['zabbixID']
            }).json()['result']['hostids']

            # Add the sophos item
            requests.post("http://localhost:5000/zabbix/additem", data=newhostid[0], headers={
                "x-access-token": current_user['zabbixauth'],
                "x-request-id": current_user['zabbixID']
            })

            # Add the sophos trigger
            print(requests.post("http://localhost:5000/zabbix/addtrigger", data=x, headers={
                "x-access-token": current_user['zabbixauth'],
                "x-request-id": current_user['zabbixID']
            }).json())

    return jsonify(message='Added missing hosts: ' + str(notpresent), code=200)


@app.route("/test")
def test():
    login = requests.post("http://localhost:5000/sophos/login", json={
        "client_id": "d4c82aff-efd3-4ec8-a040-685434d5d690",
        "client_secret":
            "5427d5c01745f0768d2bea887cd4f7c90bed805587edab1b4d3ac12949fe691c6961b5b1685a47d0f34d66d6733f89f59c09"
    }).json()
    whoami = requests.get("http://localhost:5000/sophos/whoami",
                          json={
                              "Authorization": login['access_token'],
                              "token_type": login['token_type'].capitalize()
                          }).json()

    token = login['token_type'].capitalize() + " " + login['access_token']

    # requests.get("http://localhost:5000/sophos/gethealth",
    #                     headers={
    #                         "Authorization": token,
    #                         "X-Tenant-ID": whoami['id'],
    #                         "X-Region": whoami['apiHosts']['dataRegion']
    #                     }).json()

    endpoints = requests.get("http://localhost:5000/sophos/getendpoints",
                             headers={
                                 "Authorization": token,
                                 "X-Tenant-ID": whoami['id'],
                                 "X-Region": whoami['apiHosts']['dataRegion']
                             }).json()

    zabbix_login = requests.get("http://localhost:5000/zabbix/login").json()
    print(token + '\n' +
          whoami['id'] + '\n' +
          whoami['apiHosts']['dataRegion'] + '\n' +
          zabbix_login['token'] + '\n' +
          str(zabbix_login['id']))

    # # Quasi sicuramente uguali o maggiori
    # zabbix_hosts = requests.get("http://localhost:5000/zabbix/gethosts", headers={
    #     "x-access-token": zabbix_login['token'],
    #     "x-request-id": str(zabbix_login['id'])
    # }).json()
    #
    # # Possono essere minori
    # sophos_endpoints = get_sophos_hostnames(endpoints)
    # hosts_list = get_zabbix_hostnames(zabbix_hosts)
    #
    # notpresent = check_hosts(hosts_list, sophos_endpoints)
    #
    # # If host is not present on Zabbix
    # # add it as host and add the sophos health trapper
    # if len(notpresent) != 0:
    #     for x in notpresent:
    #         # Add the missing host
    #         newhostid = requests.post("http://localhost:5000/zabbix/addhost", data=x, headers={
    #             "x-access-token": zabbix_login['token'],
    #             "x-request-id": str(zabbix_login['id'])
    #         }).json()['result']['hostids']
    #
    #         # Add the sophos item
    #         requests.post("http://localhost:5000/zabbix/additem", data=newhostid[0], headers={
    #             "x-access-token": zabbix_login['token'],
    #             "x-request-id": str(zabbix_login['id'])
    #         })
    #
    #         # Add the sophos trigger
    #         print(requests.post("http://localhost:5000/zabbix/addtrigger", data=x, headers={
    #             "x-access-token": zabbix_login['token'],
    #             "x-request-id": str(zabbix_login['id'])
    #         }).json())
    #
    # cartella_clinica = check_sophos_health(endpoints)
    # for item in cartella_clinica:
    #     alert = {
    #         "hostname": item['hostname'],
    #         "health": item['health']
    #     }
    #
    #     requests.post("http://localhost:5000/zabbix/sendalert", json=alert, headers={
    #         "x-access-token": zabbix_login['token'],
    #         "x-request-id": str(zabbix_login['id'])
    #     })
    #
    # return "Hello"


if __name__ == '__main__':
    app.run(debug=True)
