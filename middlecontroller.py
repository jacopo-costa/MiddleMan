from time import sleep

import sophos
import zabbix

flag = True
tokenExpired = False


def hostcheck(region, sophosauth, sophosID, zabbixauth, zabbixID):
    while flag:
        try:
            groupid = zabbix.get_host_group(zabbixID, zabbixauth, 'Sophos group')

            if len(groupid['result']) == 0:
                groupid = zabbix.add_host_group(zabbixID, zabbixauth, 'Sophos group')['result']['groupids'][0]
            else:
                groupid = groupid['result'][0]['groupid']

            sophos_endpoints = get_sophos_hostnames(sophos.list_endpoints(region, sophosauth, sophosID))
            zabbix_hosts = get_zabbix_hostnames(zabbix.list_hosts(zabbixID, zabbixauth))
            notpresent = find_missing(zabbix_hosts, sophos_endpoints)

            if len(notpresent) != 0:
                for x in notpresent:
                    print("Aggiungo l'host: {}".format(x))
                    services = sophos_get_services(x, region, sophosID, sophosauth)
                    hostid = zabbix.add_host(zabbixID, zabbixauth, x, groupid)['result']['hostids']
                    for i in services:
                        print("\tAggiungo il servizio: {}".format(i))
                        zabbix.add_item(zabbixID, zabbixauth, hostid[0], i['name'], i['name'].lower().replace(' ', '.'))
                        zabbix.add_trigger(zabbixID, zabbixauth, '{} ha smesso di funzionare'.format(i['name']),
                                           'last(/{}/{})<>"running"'.format(x, i['name'].lower().replace(' ', '.')))

            # cartella_clinica = check_sophos_health(sophos.list_endpoints(region, sophosauth, sophosID))
            # for item in cartella_clinica:
            #     zabbix.send_alert(item['hostname'], item['health'])
        except:
            global tokenExpired
            tokenExpired = True
        sleep(120)


def sophos_get_services(x, region, sophosID, sophosauth):
    return \
        sophos.get_endpoint(region, sophosauth, sophosID, '', '?hostnameContains=' + x)['items'][0]['health'][
            'services'][
            'serviceDetails']


def missing_group(zabbixauth, zabbixID, zabbix_hosts):
    nogroup = []

    for i in zabbix_hosts:
        groups = zabbix.get_host_groups(zabbixID, zabbixauth, i)['result'][0]['hostgroups']
        localflag = False
        for x in groups:
            if x['name'] == 'Sophos group':
                localflag = True

        if not localflag:
            nogroup.append(i)


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
