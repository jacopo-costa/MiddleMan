import logging
import time
from time import sleep

import global_vars as gl
import sophos
import zabbix


def check_alerts():
    five_minutes_ago = int(time.time()) - 5 * 60
    alerts = sophos.last_24h_alerts('?from_date=' + str(five_minutes_ago))

    for alert in alerts['items']:
        if alert['severity'] == 'low':
            zabbix.send_alert('Sophos Alerts', 'sophos.alert.low', alert['description'])
        elif alert['severity'] == 'medium':
            zabbix.send_alert('Sophos Alerts', 'sophos.alert.medium', alert['description'])
        elif alert['severity'] == 'high':
            zabbix.send_alert('Sophos Alerts', 'sophos.alert.high', alert['description'])


def check_firewall_connection():
    sophos_firewalls = sophos.get_firewalls()
    for firewall in sophos_firewalls['items']:
        if not firewall['status']['connected']:
            zabbix.send_alert(firewall['name'], 'connected', 'false')
        else:
            zabbix.send_alert(firewall['name'], 'connected', 'true')


def check_group(hostname, group):
    groups = zabbix.get_host_groups(hostname)['result'][0]['hostgroups']
    flag = False
    newgroups = []
    for x in groups:
        newgroups.append({"groupid": x['groupid']})
        if x['name'] == group:
            flag = True

    if not flag:
        newgroups.append({"groupid": zabbix.get_host_group(group)['result'][0]['groupid']})
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
            zabbix.add_trigger('{} stopped working'.format(i['name']),
                               'last(/{}/{})<>"running"'.format(hostname, i['name'].lower().replace(' ', '.')))
        if not health:
            zabbix.add_item(hostid, 'Sophos Health', 'sophos.health')
            zabbix.add_trigger('{} has a problem'.format(hostname),
                               'last(/{}/{})<>"good"'.format(hostname, 'sophos.health'))


def check_services_status(endpoints):
    sophos_endpoints = get_sophos_hostnames(endpoints)
    for host in sophos_endpoints:
        services = sophos_get_services(host)
        for serv in services:
            zabbix.send_alert(host, serv['name'].lower().replace(' ', '.'), serv['status'])


def check_sophos_health(endpoints):
    for key in endpoints['items']:
        zabbix.send_alert(key['hostname'], 'sophos.health', key['health']['overall'])


def find_missing(zabbix_list, sophos_list):
    notpresent = []

    for item in sophos_list:
        if zabbix_list.__contains__(item):
            pass
        else:
            notpresent.append(item)

    return notpresent


def first_check():
    first_check_hosts()
    first_check_firewalls()
    first_check_alerts()


def first_check_alerts():
    groupid = zabbix.get_host_group('Sophos group')['result'][0]['groupid']
    if len(zabbix.get_host('Sophos Alerts')['result']) == 0:
        hostid = zabbix.add_host('Sophos Alerts', groupid)['result']['hostids']
        zabbix.add_item(hostid[0], 'Sophos Alert Low', 'sophos.alert.low')
        zabbix.add_item(hostid[0], 'Sophos Alert Medium', 'sophos.alert.medium')
        zabbix.add_item(hostid[0], 'Sophos Alert High', 'sophos.alert.high')


def first_check_firewalls():
    groupid = zabbix.get_host_group('Firewalls group')

    # Check if the group exist, else create it
    if len(groupid['result']) == 0:
        logging.info('Adding missing')
        groupid = zabbix.add_host_group('Firewalls group')['result']['groupids'][0]
    else:
        groupid = groupid['result'][0]['groupid']

    sophos_firewalls = get_firewall_names(sophos.get_firewalls())
    zabbix_hosts = get_zabbix_hostnames(zabbix.list_hosts())
    # Get a list of hosts present on Sophos and not on Zabbix
    notpresent = find_missing(zabbix_hosts, sophos_firewalls)
    alreadypresent = get_present(zabbix_hosts, sophos_firewalls)

    # Add the found hosts with their items and triggers linked to their services
    if len(notpresent) != 0:
        for x in notpresent:
            logging.info("Adding firewall: {}".format(x))
            hostid = zabbix.add_host(x, groupid)['result']['hostids']
            logging.info("\tAdding connected item")
            zabbix.add_item(hostid[0], 'Connected', 'connected')
            zabbix.add_trigger('{} is offline'.format(x),
                               'last(/{}/{})<>"true"'.format(x, 'connected'))

    for i in alreadypresent:
        check_group(i, 'Firewalls group')


def first_check_hosts():
    groupid = zabbix.get_host_group('Sophos group')

    # Check if the group exist, else create it
    if len(groupid['result']) == 0:
        logging.info('Adding missing group')
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
            logging.info("Adding host: {}".format(x))
            services = sophos_get_services(x)
            hostid = zabbix.add_host(x, groupid)['result']['hostids']
            for i in services:
                logging.info("\tAdding service: {}".format(i))
                zabbix.add_item(hostid[0], i['name'], i['name'].lower().replace(' ', '.'))
                zabbix.add_trigger('{} stopped working'.format(i['name']),
                                   'last(/{}/{})<>"running"'.format(x, i['name'].lower().replace(' ', '.')))
            logging.info("\tAdding Sophos Health item")
            zabbix.add_item(hostid[0], 'Sophos Health', 'sophos.health')
            zabbix.add_trigger('{} has a problem'.format(x),
                               'last(/{}/{})<>"good"'.format(x, 'sophos.health'))

    for i in alreadypresent:
        check_group(i, 'Sophos group')
        check_items(i)


def get_firewall_names(firewalls):
    names = []
    for key in firewalls['items']:
        names.append(str(key['name']))
    return names


def get_present(zabbix_hosts, sophos_endpoints):
    present = []

    for item in sophos_endpoints:
        if zabbix_hosts.__contains__(item):
            present.append(item)
        else:
            pass

    return present


def get_sophos_hostnames(endpoints):
    hostnames = []
    for key in endpoints['items']:
        hostnames.append(str(key['hostname']))
    return hostnames


def get_zabbix_hostnames(zabbix_hosts):
    hostnames = []
    for key in zabbix_hosts['result']:
        hostnames.append(str(key['host']))
    return hostnames


def isolate_host(hosts):
    for host in hosts:
        sophos.isolate(host)


def routine():
    try:
        # Check if the hosts are present in both system and update
        first_check()
        endpoints = sophos.list_endpoints()
        cycle = 0

        while gl.thread_flag:
            cycle += 1
            logging.info("Cycle n° " + str(cycle))
            check_services_status(endpoints)
            check_sophos_health(endpoints)
            check_firewall_connection()
            check_alerts()
            sleep(300)

    except Exception as e:
        logging.error(e)
        gl.thread_flag = False
        gl.token_expired = True
        return


def sophos_get_services(x):
    return sophos.get_endpoint('', '?hostnameContains=' + x)['items'][0]['health']['services']['serviceDetails']


def start_scan(hostname):
    hostid = sophos.get_endpoint('', '?hostnameContains=' + hostname)['items'][0]['id']
    logging.info(sophos.execute_scan(hostid))
