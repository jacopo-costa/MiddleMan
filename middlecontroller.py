import logging
import traceback
from time import sleep

import global_vars as gl
import sophos
import zabbix


def check_endpoint_health(report):
    for item in report:
        zabbix.send_alert(item['hostname'], 'sophos.health', item['health'])


# Check if a Host is in the Sophos group
def check_group(hostname):
    groups = zabbix.get_host_groups(hostname)['result'][0]['hostgroups']
    flag = False
    newgroups = []
    for x in groups:
        newgroups.append({"groupid": x['groupid']})
        if x['name'] == 'Sophos group':
            flag = True

    if not flag:
        newgroups.append({"groupid": zabbix.get_host_group('Sophos group')['result'][0]['groupid']})
        zabbix.update_host_groups(zabbix.get_host(hostname)['result'][0]['hostid'], newgroups)


def check_items(hostname):
    hostid = zabbix.get_host(hostname)['result'][0]['hostid']
    items = zabbix.get_items(hostid)['result']
    services = sophos_get_services(hostname)

    for i in services:
        flag = False
        health = False
        for x in items:
            if x['name'] == i['name']:
                flag = True
            if x['name'] == 'Sophos Health':
                health = True
        if not flag:
            zabbix.add_item(hostid, i['name'], i['name'].lower().replace(' ', '.'))
            zabbix.add_trigger('{} ha smesso di funzionare'.format(i['name']),
                               'last(/{}/{})<>"running"'.format(hostname, i['name'].lower().replace(' ', '.')))
        if not health:
            zabbix.add_item(hostid, 'Sophos Health', 'sophos.health')
            zabbix.add_trigger('{} ha un problema'.format(hostname),
                               'last(/{}/{})<>"good"'.format(hostname, 'sophos.health'))


# Get the active services for the host
def check_services_status():
    sophos_endpoints = get_sophos_hostnames(sophos.list_endpoints())
    for host in sophos_endpoints:
        services = sophos_get_services(host)
        for serv in services:
            if serv['status'] != 'running':
                zabbix.send_alert(host, serv['name'].lower().replace(' ', '.'), serv['status'])


def check_sophos_health(endpoints):
    health_check = []

    for key in endpoints['items']:
        if str(key['health']['overall']) != 'good':
            health_check.append({
                "hostname": str(key['hostname']),
                "health": str(key['health']['overall'])
            })

    return health_check


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


# First scan at the start of the Thread, check if hosts have the group, items and trigger
# correctly assigned
def first_check():
    groupid = zabbix.get_host_group('Sophos group')

    # Check if the group exist, else create it
    if len(groupid['result']) == 0:
        logging.info('Aggiungo il gruppo mancante')
        groupid = zabbix.add_host_group('Sophos group')['result']['groupids'][0]
    else:
        groupid = groupid['result'][0]['groupid']

    sophos_endpoints = get_sophos_hostnames(sophos.list_endpoints())
    zabbix_hosts = get_zabbix_hostnames(zabbix.list_hosts())
    # Get a list of hosts present on Sophos and not on Zabbix
    notpresent = find_missing(zabbix_hosts, sophos_endpoints)
    alreadypresent = get_present(zabbix_hosts, sophos_endpoints)

    # Add the found hosts with their items and triggers linked to their services
    if len(notpresent) != 0:
        for x in notpresent:
            logging.info("Aggiungo l'host: {}".format(x))
            services = sophos_get_services(x)
            hostid = zabbix.add_host(x, groupid)['result']['hostids']
            for i in services:
                logging.info("\tAggiungo il servizio: {}".format(i))
                zabbix.add_item(hostid[0], i['name'], i['name'].lower().replace(' ', '.'))
                zabbix.add_trigger('{} ha smesso di funzionare'.format(i['name']),
                                   'last(/{}/{})<>"running"'.format(x, i['name'].lower().replace(' ', '.')))
            logging.info("\tAggiungo l'item Sophos Health")
            zabbix.add_item(hostid[0], 'Sophos Health', 'sophos.health')
            zabbix.add_trigger('{} ha un problema'.format(x),
                               'last(/{}/{})<>"good"'.format(x, 'sophos.health'))

    for i in alreadypresent:
        check_group(i)
        check_items(i)


# Check if a host in Zabbix have all Sophos services as items
def get_present(zabbix_hosts, sophos_endpoints):
    present = []

    for item in sophos_endpoints:
        if zabbix_hosts.__contains__(item):
            present.append(item)
        else:
            pass

    return present


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
# Add to a list if found
def isolate_host(hosts):
    for host in hosts:
        sophos.isolate(host)


# Routine Thread, do a first check then enter the loop
def routine():
    try:
        # Check if the hosts are present in both system and update
        first_check()

        while gl.thread_flag:
            check_services_status()
            report = check_sophos_health(sophos.list_endpoints())
            if report:
                for host in report:
                    zabbix.send_alert(host['hostname'], 'sophos.health', host['health'])
                    start_scan(host['hostname'])
            sleep(300)

    except Exception:
        traceback.print_exc()
        gl.thread_flag = False
        gl.token_expired = True
        return


def sophos_get_services(x):
    return sophos.get_endpoint('', '?hostnameContains=' + x)['items'][0]['health']['services']['serviceDetails']


def start_scan(hostname):
    hostid = sophos.get_endpoint('', '?hostnameContains=' + hostname)['items'][0]['id']
    logging.info(sophos.execute_scan(hostid))
