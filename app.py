"""
logging: implicit
os: To get the environment variables passed by Docker
sys: To exit in case the environment variables are not set
threading: Start a thread with the controller
time: Import for the sleep function
"""
import logging
import os
import sys
import threading
from time import sleep

import config as cfg
import middlecontroller
import sophos
import zabbix

# logging config with timestamp
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', level=logging.INFO, datefmt='%d-%m-%Y %H:%M:%S')


def login():
    """
    Login into Sophos and Zabbix with data passed by
    Docker environment variables.
    Save the tokens on the config file.
    :return:
    """
    try:
        sid = os.environ['SOPHOS_ID']
        secret = os.environ['SOPHOS_SECRET']
        zuser = os.environ['ZABBIX_USER']
        zpass = os.environ['ZABBIX_PASS']
        cfg.url_zabbix = "http://{}:{}/api_jsonrpc.php".format(os.environ['ZABBIX_HOSTNAME'], os.environ['ZABBIX_PORT'])
        cfg.tenant_name = os.environ['TENANT_NAME']
    except KeyError:
        logging.error("Environment variables not set")
        sys.exit(1)

    slogin = sophos.login(sid, secret)
    whoami = sophos.whoami(slogin)
    token = slogin['token_type'].capitalize() + " " + slogin['access_token']

    zabbix_login = zabbix.login(zuser, zpass)

    cfg.sophos_auth = token
    cfg.sophos_id = whoami['id']
    cfg.region = whoami['apiHosts']['dataRegion']
    cfg.zabbix_auth = zabbix_login['result']
    cfg.zabbix_id = zabbix_login['id']


def re_login():
    """
    Request a new Sophos token
    :return:
    """
    sid = os.environ['SOPHOS_ID']
    secret = os.environ['SOPHOS_SECRET']

    slogin = sophos.login(sid, secret)
    whoami = sophos.whoami(slogin)
    token = slogin['token_type'].capitalize() + " " + slogin['access_token']

    cfg.sophos_auth = token
    cfg.sophos_id = whoami['id']
    cfg.region = whoami['apiHosts']['dataRegion']


def start_middleman():
    """
    Start the thread with the check routine.
    :return:
    """
    try:
        cfg.thread_flag = True
        middlethread = threading.Thread(target=middlecontroller.routine, name='middleman')
        middlethread.start()
    except RuntimeError as run_err:
        cfg.thread_flag = False
        logging.error(run_err)


def token_checker():
    """
    About every hour the Sophos token expires.
    Check if the token is expired
    every 5 minutes.
    In that case re-do the login and relaunch the thread.
    :return:
    """
    while True:
        if cfg.token_expired:
            logging.info('Requested new token')
            re_login()
            cfg.token_expired = False
            start_middleman()
        sleep(300)


if __name__ == '__main__':
    logging.info("MiddleMan started")
    login()
    start_middleman()
    token_checker()
