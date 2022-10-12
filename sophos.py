import requests

url_token = "https://id.sophos.com/api/v2/oauth2/token"
url_id = "https://api.central.sophos.com/whoami/v1"


def login(client_id, client_secret):
    data = "grant_type=client_credentials&client_id=" + client_id + "&client_secret=" + client_secret + "&scope=token"
    return requests.post(url_token, headers={"Content-Type": "application/x-www-form-urlencoded"}, data=data).json()


def whoami(login):
    authorization = login['token_type'].capitalize() + " " + login['access_token']

    return requests.get(url_id, headers={"Authorization": authorization}).json()


def list_endpoints(region, auth, id):
    return requests.get(region + "/endpoint/v1/endpoints", headers={"Authorization": auth, "X-Tenant-ID": id}).json()

def get_endpoint(region, auth, id, hostnameid, query):
    if query:
        return requests.get(region + "/endpoint/v1/endpoints/" + query,
                        headers={"Authorization": auth, "X-Tenant-ID": id}).json()
    else:
        return requests.get(region + "/endpoint/v1/endpoints/" + hostnameid,
                            headers={"Authorization": auth, "X-Tenant-ID": id}).json()
