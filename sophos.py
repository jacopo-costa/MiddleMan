import requests

import global_vars as gl

url_token = "https://id.sophos.com/api/v2/oauth2/token"
url_id = "https://api.central.sophos.com/whoami/v1"


def login(client_id, client_secret):
    data = "grant_type=client_credentials&client_id=" + client_id + "&client_secret=" + client_secret + "&scope=token"
    return requests.post(url_token, headers={"Content-Type": "application/x-www-form-urlencoded"}, data=data).json()


def whoami(login_data):
    authorization = login_data['token_type'].capitalize() + " " + login_data['access_token']

    return requests.get(url_id, headers={"Authorization": authorization}).json()


def list_endpoints():
    return requests.get(gl.region + "/endpoint/v1/endpoints",
                        headers={"Authorization": gl.sophos_auth, "X-Tenant-ID": gl.sophos_id}).json()


def get_endpoint(hostnameid, query):
    if query:
        return requests.get(gl.region + "/endpoint/v1/endpoints/" + query,
                            headers={"Authorization": gl.sophos_auth, "X-Tenant-ID": gl.sophos_id}).json()
    else:
        return requests.get(gl.region + "/endpoint/v1/endpoints/" + hostnameid,
                            headers={"Authorization": gl.sophos_auth, "X-Tenant-ID": gl.sophos_id}).json()

def get_endpoints_groups():
    return requests.get(gl.region + "/endpoint/v1/endpoint-groups",
                        headers={"Authorization": gl.sophos_auth, "X-Tenant-ID": gl.sophos_id}).json()
