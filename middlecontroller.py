import logging
import time
from time import sleep

import config as cfg
import sophos
import zabbix


def check_alerts():
    """
    Get the alerts from the past 5 minutes.
    If there is any send an alert to the appropriate
    Zabbix item.
    :return:
    """
    five_minutes_ago = int(time.time()) - 5 * 60
    alerts = sophos.last_24h_alerts('?from_date=' + str(five_minutes_ago))

    for alert in alerts['items']:
        if alert['severity'] == 'low':
            zabbix.send_alert(alert['location'], 'sophos.alert.low', alert['description'])
        elif alert['severity'] == 'medium':
            zabbix.send_alert(alert['location'], 'sophos.alert.medium', alert['description'])
        elif alert['severity'] == 'high':
            zabbix.send_alert(alert['location'], 'sophos.alert.high', alert['description'])


def check_events():
    """
    Get the events from the past 5 minutes.
    If there is any send an alert to the appropriate
    Zabbix item.
    :return:
    """
    five_minutes_ago = int(time.time()) - 5 * 60
    events = sophos.last_24h_events('?from_date=' + str(five_minutes_ago))

    for event in events['items']:
        if event['severity'] == 'low':
            zabbix.send_alert(event['location'], 'sophos.event.low', event['name'])
        elif event['severity'] == 'medium':
            zabbix.send_alert(event['location'], 'sophos.event.medium', event['name'])
        elif event['severity'] == 'high':
            zabbix.send_alert(event['location'], 'sophos.event.high', event['name'])
        elif event['severity'] == 'none':
            zabbix.send_alert(event['location'], 'sophos.event.none', event['name'])
        elif event['severity'] == 'critical':
            zabbix.send_alert(event['location'], 'sophos.event.critical', event['name'])


def check_firewall_connection():
    """
    Get the firewalls data and send an alert
    if they are offline.
    :return:
    """
    sophos_firewalls = sophos.get_firewalls()
    for firewall in sophos_firewalls['items']:
        if not firewall['status']['connected']:
            zabbix.send_alert(firewall['name'], 'connected', 'false')
        else:
            zabbix.send_alert(firewall['name'], 'connected', 'true')


def check_group(hostname, group):
    """
    Check if the passed group name is present
    in the host groups list.
    Else add it.
    :param hostname: Host to check
    :param group: Group name to search
    :return:
    """
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
    """
    Check if a Host has saved every item for its services
    and the Sophos Health.
    If not add it.
    :param hostname: Host to check
    :return:
    """
    hostid = zabbix.get_host(hostname)['result'][0]['hostid']
    items = zabbix.get_items(hostid)['result']
    services = sophos_get_services(hostname)

    for alert in cfg.alerts:
        zabbix.add_item(hostid, alert, alert.lower().replace(' ', '.'))

    for event in cfg.events:
        zabbix.add_item(hostid, event, event.lower().replace(' ', '.'))

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
                               'last(/{}/{})<>"running"'.format(hostname, i['name'].lower().replace(' ', '.')), 2)
        if not health:
            zabbix.add_item(hostid, 'Sophos Health', 'sophos.health')
            zabbix.add_trigger('{} has a problem'.format(hostname),
                               'last(/{}/{})<>"good"'.format(hostname, 'sophos.health'), 2)


def check_services_status(endpoints):
    """
    Update the status for every service and
    send it to Zabbix
    :param endpoints: Endpoints list from Sophos
    :return:
    """
    sophos_endpoints = get_sophos_hostnames(endpoints)
    for host in sophos_endpoints:
        services = sophos_get_services(host)
        for serv in services:
            zabbix.send_alert(host, serv['name'].lower().replace(' ', '.'), serv['status'])


def check_sophos_health(endpoints):
    """
    Update the health check for every endpoint
    and send it to Zabbix
    :param endpoints: Endpoints list from Sophos
    :return:
    """
    for key in endpoints['items']:
        zabbix.send_alert(key['hostname'], 'sophos.health', key['health']['overall'])


def find_missing(zabbix_hosts, sophos_endpoints):
    """
    Confront the list of host on the systems,
    if there are discrepancies append to the list.
    :param zabbix_hosts: List of hosts in Zabbix
    :param sophos_endpoints: List of endpoints in Sophos
    :return: List of hostnames present only on Sophos
    """
    notpresent = []

    for item in sophos_endpoints:
        if zabbix_hosts.__contains__(item):
            pass
        else:
            notpresent.append(item)

    return notpresent


def first_check():
    """
    Aggregate function for the first checks
    :return:
    """
    first_check_hosts()
    first_check_firewalls()
    #first_check_alerts()
    #first_check_events()


def first_check_alerts():
    """
    Check if the Sophos Alerts host is present on Zabbix with
    the low, medium and high items.
    If not add them.
    :return:
    """
    groupid = zabbix.get_host_group('Sophos group')['result'][0]['groupid']
    if len(zabbix.get_host('Sophos Alerts')['result']) == 0:
        hostid = zabbix.add_host('Sophos Alerts', groupid)['result']['hostids']
        zabbix.add_item(hostid[0], 'Sophos Alert Low', 'sophos.alert.low')
        zabbix.add_item(hostid[0], 'Sophos Alert Medium', 'sophos.alert.medium')
        zabbix.add_item(hostid[0], 'Sophos Alert High', 'sophos.alert.high')


def first_check_events():
    """
    Check if the Sophos Events host is present on Zabbix with
    the low, medium and high items.
    If not add them.
    :return:
    """
    groupid = zabbix.get_host_group('Sophos group')['result'][0]['groupid']
    if len(zabbix.get_host('Sophos Events')['result']) == 0:
        hostid = zabbix.add_host('Sophos Events', groupid)['result']['hostids']
        zabbix.add_item(hostid[0], 'Sophos Event None', 'sophos.event.none')
        zabbix.add_item(hostid[0], 'Sophos Event Low', 'sophos.event.low')
        zabbix.add_item(hostid[0], 'Sophos Event Medium', 'sophos.event.medium')
        zabbix.add_item(hostid[0], 'Sophos Event High', 'sophos.event.high')
        zabbix.add_item(hostid[0], 'Sophos Event Critical', 'sophos.event.critical')


def first_check_firewalls():
    """
    Check if the firewalls host and group are present on Zabbix.
    If not add them with the connected item.
    :return:
    """
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
                               'last(/{}/{})<>"true"'.format(x, 'connected'), 2)
            for alert in cfg.alerts:
                logging.info("\tAdding alert: {}".format(alert))
                zabbix.add_item(hostid[0], alert, alert.lower().replace(' ', '.'))

            for event in cfg.events:
                logging.info("\tAdding event: {}".format(event))
                zabbix.add_item(hostid[0], event, event.lower().replace(' ', '.'))

    for i in alreadypresent:
        check_group(i, 'Firewalls group')
        # Check if connected item is present
        hostid = zabbix.get_host(i)['result'][0]['hostid']
        items = zabbix.get_items(hostid)['result']
        for item in items:
            flag = False
            if item['name'] == 'Connected':
                flag = True
            if not flag:
                zabbix.add_item(hostid[0], 'Connected', 'connected')
                zabbix.add_trigger('{} is offline'.format(i),
                                   'last(/{}/{})<>"true"'.format(i, 'connected'), 2)
        for alert in cfg.alerts:
            zabbix.add_item(hostid[0], alert, alert.lower().replace(' ', '.'))

        for event in cfg.events:
            zabbix.add_item(hostid[0], event, event.lower().replace(' ', '.'))


def first_check_hosts():
    """
    Check if the hosts and the Sophos group are present on Zabbix.
    If not add them with the associated items for their services,
    the Sophos Health and the events/alerts.
    :return:
    """
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
                logging.info("\tAdding service: {}".format(i['name']))
                zabbix.add_item(hostid[0], i['name'], i['name'].lower().replace(' ', '.'))
                zabbix.add_trigger('{} stopped working'.format(i['name']),
                                   'last(/{}/{})<>"running"'.format(x, i['name'].lower().replace(' ', '.')), 2)

            for alert in cfg.alerts:
                logging.info("\tAdding alert: {}".format(alert))
                zabbix.add_item(hostid[0], alert, alert.lower().replace(' ', '.'))

            for event in cfg.events:
                logging.info("\tAdding event: {}".format(event))
                zabbix.add_item(hostid[0], event, event.lower().replace(' ', '.'))

            logging.info("\tAdding Sophos Health item")
            zabbix.add_item(hostid[0], 'Sophos Health', 'sophos.health')
            zabbix.add_trigger('{} has a problem'.format(x),
                               'last(/{}/{})<>"good"'.format(x, 'sophos.health'), 2)

    for i in alreadypresent:
        check_group(i, 'Sophos group')
        check_items(i)


def get_firewall_names(firewalls):
    """
    Filter the names out of the Sophos get firewalls
    :param firewalls: Firewalls data from Sophos
    :return: List of firewalls names
    """
    names = []
    for key in firewalls['items']:
        names.append(str(key['name']))
    return names


def get_present(zabbix_hosts, sophos_endpoints):
    """
    Confront the list of host on the systems,
    if they are on both system append them to the list.
    :param zabbix_hosts: List of hosts in Zabbix
    :param sophos_endpoints: List of endpoints in Sophos
    :return: List of hostnames on both systems
    """
    present = []

    for item in sophos_endpoints:
        if zabbix_hosts.__contains__(item):
            present.append(item)
        else:
            pass

    return present


def get_sophos_hostnames(endpoints):
    """
    Filter the names out of the Sophos list endpoints
    :param endpoints: Endpoints data from Sophos
    :return: List of endpoints names
    """
    hostnames = []
    for key in endpoints['items']:
        hostnames.append(str(key['hostname']))
    return hostnames


def get_zabbix_hostnames(hosts):
    """
    Filter the names out of the Zabbix get hosts
    :param hosts: hosts data from Zabbix
    :return: List of hostnames
    """
    hostnames = []
    for key in hosts['result']:
        hostnames.append(str(key['host']))
    return hostnames


def isolate_host(hosts):
    """
    For every host passed as parameted put it on isolation.
    :param hosts: Host list
    :return:
    """
    for host in hosts:
        sophos.isolate(host)


def routine():
    """
    Main function for the thread.
    At first check if there are any discrepancies on Sophos and Zabbix.
    Then enter a loop in which check the health of the systems and send
    the updated status to Zabbix.
    :return:
    """
    try:
        first_check()
        cycle = 0

        while cfg.thread_flag:
            cycle += 1
            logging.info("Cycle n° " + str(cycle))
            endpoints = sophos.list_endpoints()
            check_services_status(endpoints)
            check_sophos_health(endpoints)
            check_firewall_connection()
            check_alerts()
            check_events()
            sleep(300)

    except Exception as e:
        logging.error(e)
        cfg.thread_flag = False
        cfg.token_expired = True
        return


def sophos_get_services(hostname):
    """
    Get the services for the passed hostname
    :param hostname: Hostname to search
    :return: List of services for the host
    """
    return sophos.get_endpoint('', '?hostnameContains=' + hostname)['items'][0]['health']['services']['serviceDetails']


def start_scan(hostname):
    """
    Start a system scan for the host
    :param hostname: Host to scan
    :return:
    """
    hostid = sophos.get_endpoint('', '?hostnameContains=' + hostname)['items'][0]['id']
    sophos.execute_scan(hostid)
