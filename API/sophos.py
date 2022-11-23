import requests

import config as cfg

'''
Every function here just send a request to the Sophos API with
the appropriate headers.
Return the response in JSON.
'''


def deisolate(host):
    hostid = get_endpoint('', '?hostnameContains=' + host)['items'][0]['id']
    return requests.patch(cfg.region + "/endpoint/v1/endpoints/{}/isolation".format(hostid),
                          headers={"Authorization": cfg.sophos_auth, "X-Tenant-ID": cfg.sophos_id},
                          json={"enabled": "false",
                                "comment": "Remove {} from isolation".format(host)}
                          ).json()


def execute_scan(hostid):
    return requests.post(cfg.region + "/endpoint/v1/endpoints/{}/scans".format(hostid),
                         headers={"Authorization": cfg.sophos_auth,
                                  "X-Tenant-ID": cfg.sophos_id},
                         json={}).json()


def get_alerts(query):
    if query:
        return requests.get(cfg.region + "/common/v1/alerts" + query,
                            headers={"Authorization": cfg.sophos_auth,
                                     "X-Tenant-ID": cfg.sophos_id}).json()
    else:
        return requests.get(cfg.region + "/common/v1/alerts",
                            headers={"Authorization": cfg.sophos_auth,
                                     "X-Tenant-ID": cfg.sophos_id}).json()


def get_endpoint(hostid, query):
    if query:
        return requests.get(cfg.region + "/endpoint/v1/endpoints/" + query,
                            headers={"Authorization": cfg.sophos_auth,
                                     "X-Tenant-ID": cfg.sophos_id}).json()
    else:
        return requests.get(cfg.region + "/endpoint/v1/endpoints/" + hostid,
                            headers={"Authorization": cfg.sophos_auth,
                                     "X-Tenant-ID": cfg.sophos_id}).json()


def get_endpoints_groups():
    return requests.get(cfg.region + "/endpoint/v1/endpoint-groups",
                        headers={"Authorization": cfg.sophos_auth,
                                 "X-Tenant-ID": cfg.sophos_id}).json()


def get_firewalls():
    return requests.get(cfg.region + "/firewall/v1/firewalls",
                        headers={"Authorization": cfg.sophos_auth,
                                 "X-Tenant-ID": cfg.sophos_id}).json()


def health_check():
    return requests.get(cfg.region + "/account-health-check/v1/health-check",
                        headers={"Authorization": cfg.sophos_auth,
                                 "X-Tenant-ID": cfg.sophos_id}).json()


def isolate(host):
    hostid = get_endpoint('', '?hostnameContains=' + host)['items'][0]['id']
    return requests.patch(cfg.region + "/endpoint/v1/endpoints/{}/isolation".format(hostid),
                          headers={"Authorization": cfg.sophos_auth, "X-Tenant-ID": cfg.sophos_id},
                          json={"enabled": "true",
                                "comment": "Isolating " + host}
                          ).json()


def last_24h_alerts(query):
    if query:
        return requests.get(cfg.region + "/siem/v1/alerts" + query,
                            headers={"Authorization": cfg.sophos_auth,
                                     "X-Tenant-ID": cfg.sophos_id}).json()
    else:
        return requests.get(cfg.region + "/siem/v1/alerts",
                            headers={"Authorization": cfg.sophos_auth,
                                     "X-Tenant-ID": cfg.sophos_id}).json()


def last_24h_events(query):
    if query:
        return requests.get(cfg.region + "/siem/v1/events" + query,
                            headers={"Authorization": cfg.sophos_auth,
                                     "X-Tenant-ID": cfg.sophos_id}).json()
    else:
        return requests.get(cfg.region + "/siem/v1/events",
                            headers={"Authorization": cfg.sophos_auth,
                                     "X-Tenant-ID": cfg.sophos_id}).json()


def list_endpoints():
    return requests.get(cfg.region + "/endpoint/v1/endpoints",
                        headers={"Authorization": cfg.sophos_auth,
                                 "X-Tenant-ID": cfg.sophos_id}).json()


def login(client_id, client_secret):
    data = "grant_type=client_credentials&client_id=" + client_id + "&client_secret=" + client_secret + "&scope=token"
    return requests.post(cfg.url_sophos_login, headers={"Content-Type": "application/x-www-form-urlencoded"},
                         data=data).json()


def whoami(login_data):
    authorization = login_data['token_type'].capitalize() + " " + login_data['access_token']
    return requests.get(cfg.url_sophos_whoami, headers={"Authorization": authorization}).json()
