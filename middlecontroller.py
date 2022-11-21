"""
logging: Implicit
time: Sleep on thread and get current time
"""
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
            zabbix.send_alert(alert['location'], 'c_sophos.alert.low', alert['description'])
        elif alert['severity'] == 'medium':
            zabbix.send_alert(alert['location'], 'c_sophos.alert.medium', alert['description'])
        elif alert['severity'] == 'high':
            zabbix.send_alert(alert['location'], 'c_sophos.alert.high', alert['description'])


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
            zabbix.send_alert(event['location'], 'c_sophos.event.low', event['name'])
        elif event['severity'] == 'medium':
            zabbix.send_alert(event['location'], 'c_sophos.event.medium', event['name'])
        elif event['severity'] == 'high':
            zabbix.send_alert(event['location'], 'c_sophos.event.high', event['name'])
        elif event['severity'] == 'none':
            zabbix.send_alert(event['location'], 'c_sophos.event.none', event['name'])
        elif event['severity'] == 'critical':
            zabbix.send_alert(event['location'], 'c_sophos.event.critical', event['name'])


def check_firewall_connection():
    """
    Get the firewalls data and send an alert
    with their status.
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
    newgroups = []
    for x in groups:
        if x['name'] == group:
            return
        newgroups.append({"groupid": x['groupid']})

    # Get the groupid from zabbix and append it to the newgroups list
    newgroups.append({"groupid": zabbix.get_host_group(group)['result'][0]['groupid']})
    logging.info("Adding {} to the {} group".format(hostname, group))
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
    exist = False

    for i in services:
        for x in items:
            exist = False
            # Iterate every item of the host
            # if the item is already there break the loop
            if x['name'] == i['name']:
                exist = True
                break

        if not exist:
            zabbix.add_item(hostid, i['name'], i['name'].lower().replace(' ', '.'))
            logging.info("Adding item {} to {}".format(i['name'], hostname))
            zabbix.add_trigger('{} stopped working'.format(i['name']),
                               'last(/{}/{})<>"running"'.format(hostname, i['name'].lower().replace(' ', '.')), 2)


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
        zabbix.send_alert(key['hostname'], 'c_sophos.health', key['health']['overall'])


def check_template(hostname, templateid):
    """
    Check if the host is already linked to the
    template, if not add it
    :param hostname:
    :param templateid:
    :return:
    """
    hostid = zabbix.get_host(hostname)['result'][0]['hostid']
    templates_list = zabbix.get_linked_templates(hostid)['result'][0]['parentTemplates']

    for item in templates_list:
        if item['templateid'] == templateid:
            return

    template = {'templateid': templateid}
    templates_list.append(template)

    logging.info("Linking the template to {}".format(hostname))
    zabbix.update_host_templates(hostid, templates_list)


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


def first_check_firewalls():
    """
    Check if the firewalls host and group are present on Zabbix.
    If not add them with the connected item.
    :return:
    """
    groupid = zabbix.get_host_group("{} Firewalls".format(cfg.tenant_name))

    # Check if the group exist, else create it
    if len(groupid['result']) == 0:
        logging.info('Adding missing firewalls group')
        groupid = zabbix.add_host_group("{} Firewalls".format(cfg.tenant_name))['result']['groupids'][0]
    else:
        groupid = groupid['result'][0]['groupid']

    # Check if the template exist, else create it and return the ID
    templateid = first_check_template("Firewalls")

    sophos_firewalls = get_firewall_names(sophos.get_firewalls())
    zabbix_hosts = get_zabbix_hostnames(zabbix.list_hosts())
    # Get a list of hosts present on Sophos and not on Zabbix
    notpresent = find_missing(zabbix_hosts, sophos_firewalls)
    alreadypresent = get_present(zabbix_hosts, sophos_firewalls)

    # Add the found hosts with their items and triggers linked to their services
    if len(notpresent) != 0:
        for x in notpresent:
            logging.info("Adding firewall: {}".format(x))
            zabbix.add_host(x, groupid, templateid)

    for i in alreadypresent:
        check_group(i, "{} Firewalls".format(cfg.tenant_name))
        check_template(i, templateid)


def first_check_hosts():
    """
    Check if the hosts and the Sophos group are present on Zabbix.
    If not add them with the associated items for their services,
    the Sophos Health and the events/alerts.
    :return:
    """
    groupid = zabbix.get_host_group("{} Hosts".format(cfg.tenant_name))

    # Check if the group exist, else create it
    if len(groupid['result']) == 0:
        logging.info('Adding missing hosts group')
        groupid = zabbix.add_host_group("{} Hosts".format(cfg.tenant_name))['result']['groupids'][0]
    else:
        groupid = groupid['result'][0]['groupid']

    # Check if the template exist, else create it and return the ID
    templateid = first_check_template("Hosts")

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
            hostid = zabbix.add_host(x, groupid, templateid)['result']['hostids']

            for i in services:
                logging.info("\tAdding service: {}".format(i['name']))
                zabbix.add_item(hostid[0], i['name'], i['name'].lower().replace(' ', '.'))
                zabbix.add_trigger('{} stopped working'.format(i['name']),
                                   'last(/{}/{})<>"running"'.format(x, i['name'].lower().replace(' ', '.')), 2)

    for i in alreadypresent:
        check_group(i, "{} Hosts".format(cfg.tenant_name))
        check_template(i, templateid)
        check_items(i)


def first_check_template(hostype):
    """
    Check if the template group and the template
    is already on Zabbix, else create it with the
    items and triggers depending on the host type.
    :param hostype: (str) Firewalls or Hosts
    :return: Template ID
    """
    templategroupid = zabbix.get_template_group("Templates/" + cfg.tenant_name)

    # Check if the group exist, else create it
    if len(templategroupid['result']) == 0:
        logging.info('Adding missing templates group')
        templategroupid = zabbix.add_template_group("Templates/" + cfg.tenant_name)['result']['groupids'][0]
    else:
        templategroupid = templategroupid['result'][0]['groupid']

    # Tenant Hosts or Tenant Firewalls
    templatenameid = zabbix.get_template("{} {}".format(cfg.tenant_name, hostype))

    if len(templatenameid['result']) == 0:
        logging.info('Adding missing template')
        templatenameid = \
            zabbix.add_template(templategroupid, "{} {}".format(cfg.tenant_name, hostype))['result']['templateids'][0]

        alerts = ['C_Sophos Alert Low', 'C_Sophos Alert Medium', 'C_Sophos Alert High']
        events = ['C_Sophos Event None', 'C_Sophos Event Low', 'C_Sophos Event Medium', 'C_Sophos Event High',
                  'C_Sophos Event Critical']

        if hostype == "Hosts":
            for alert in alerts:
                logging.info("\tAdding alert: {}".format(alert))
                zabbix.add_item(templatenameid, alert, alert.lower().replace(' ', '.'))

            for event in events:
                logging.info("\tAdding event: {}".format(event))
                zabbix.add_item(templatenameid, event, event.lower().replace(' ', '.'))

            logging.info("\tAdding event: Sophos Health problem")
            zabbix.add_item(templatenameid, 'C_Sophos Health', 'c_sophos.health')
            zabbix.add_trigger('Sophos Health problem',
                               'last(/{} {}/{})<>"good"'.format(cfg.tenant_name, hostype, 'c_sophos.health'), 2)

        if hostype == "Firewalls":
            logging.info("\tAdding connected item")
            zabbix.add_item(templatenameid, 'Connected', 'connected')
            zabbix.add_trigger('Firewall offline',
                               'last(/{} {}/{})<>"true"'.format(cfg.tenant_name, hostype, 'connected'), 2)

            for alert in alerts:
                logging.info("\tAdding alert: {}".format(alert))
                zabbix.add_item(templatenameid, alert, alert.lower().replace(' ', '.'))

            for event in events:
                logging.info("\tAdding event: {}".format(event))
                zabbix.add_item(templatenameid, event, event.lower().replace(' ', '.'))
    else:
        templatenameid = templatenameid['result'][0]['templateid']

    return templatenameid


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
    TODO: The Tenant must have permission to do this. Right now this
          is not called.
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
    Then sleep for 5 minutes.
    :return:
    """
    try:
        first_check_hosts()
        first_check_firewalls()
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
        # The Sophos Token could expire while doing the work in the routine
        # so the Exception cannot be foreseen.
        # This catch every Exception it could happen, log the error and set the flags.
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
    TODO: The Tenant must have permission to do this. Right now this
          is not called.
    :param hostname: Host to scan
    :return:
    """
    hostid = sophos.get_endpoint('', '?hostnameContains=' + hostname)['items'][0]['id']
    sophos.execute_scan(hostid)
