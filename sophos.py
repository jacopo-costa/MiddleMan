import requests

import global_vars as gl

url_token = "https://id.sophos.com/api/v2/oauth2/token"
url_id = "https://api.central.sophos.com/whoami/v1"


def deisolate(host):
    hostid = get_endpoint('', '?hostnameContains=' + host)['items'][0]['id']
    return requests.patch(gl.region + "/endpoint/v1/endpoints/{}/isolation".format(hostid),
                          headers={"Authorization": gl.sophos_auth, "X-Tenant-ID": gl.sophos_id},
                          json={"enabled": "false",
                                "comment": "Remove {} from isolation".format(host)}
                          ).json()


def execute_scan(hostid):
    return requests.post(gl.region + "/endpoint/v1/endpoints/{}/scans".format(hostid),
                         headers={"Authorization": gl.sophos_auth,
                                  "X-Tenant-ID": gl.sophos_id},
                         json={}).json()


def get_alerts(query):
    if query:
        return requests.get(gl.region + "/common/v1/alerts" + query,
                            headers={"Authorization": gl.sophos_auth,
                                     "X-Tenant-ID": gl.sophos_id}).json()
    else:
        return requests.get(gl.region + "/common/v1/alerts",
                            headers={"Authorization": gl.sophos_auth,
                                     "X-Tenant-ID": gl.sophos_id}).json()


def get_endpoint(hostnameid, query):
    if query:
        return requests.get(gl.region + "/endpoint/v1/endpoints/" + query,
                            headers={"Authorization": gl.sophos_auth,
                                     "X-Tenant-ID": gl.sophos_id}).json()
    else:
        return requests.get(gl.region + "/endpoint/v1/endpoints/" + hostnameid,
                            headers={"Authorization": gl.sophos_auth,
                                     "X-Tenant-ID": gl.sophos_id}).json()


def get_endpoints_groups():
    return requests.get(gl.region + "/endpoint/v1/endpoint-groups",
                        headers={"Authorization": gl.sophos_auth,
                                 "X-Tenant-ID": gl.sophos_id}).json()


def health_check():
    return requests.get(gl.region + "/account-health-check/v1/health-check",
                        headers={"Authorization": gl.sophos_auth,
                                 "X-Tenant-ID": gl.sophos_id}).json()


def isolate(host):
    hostid = get_endpoint('', '?hostnameContains=' + host)['items'][0]['id']
    return requests.patch(gl.region + "/endpoint/v1/endpoints/{}/isolation".format(hostid),
                          headers={"Authorization": gl.sophos_auth, "X-Tenant-ID": gl.sophos_id},
                          json={"enabled": "true",
                                "comment": "Isolating " + host}
                          ).json()


def list_endpoints():
    return requests.get(gl.region + "/endpoint/v1/endpoints",
                        headers={"Authorization": gl.sophos_auth,
                                 "X-Tenant-ID": gl.sophos_id}).json()


def login(client_id, client_secret):
    data = "grant_type=client_credentials&client_id=" + client_id + "&client_secret=" + client_secret + "&scope=token"
    return requests.post(url_token, headers={"Content-Type": "application/x-www-form-urlencoded"}, data=data).json()


def whoami(login_data):
    authorization = login_data['token_type'].capitalize() + " " + login_data['access_token']

    return requests.get(url_id, headers={"Authorization": authorization}).json()
