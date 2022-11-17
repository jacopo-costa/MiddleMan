import logging
import os
import sys
import threading
from time import sleep

import config as cfg
import middlecontroller
import sophos
import zabbix

# app = Flask(__name__)
# app.secret_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
# CORS(app)

# Logging config with timestamp
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                    level=logging.INFO,
                    datefmt='%d-%m-%Y %H:%M:%S')

# Disable HTTP status log
logging.getLogger('werkzeug').disabled = True


# @app.route("/status")
# @cross_origin()
# def check_thread():
#     """
#     Check if the thread is running by looking at its flag
#     :return: Value of the thread flag as string
#     """
#     return str(cfg.thread_flag)


def start():
    """
    Start the thread with the check routine.
    :return: Status message as JSON
    """
    cfg.thread_flag = True
    middlethread = threading.Thread(target=middlecontroller.routine, name='middleman')
    middlethread.start()


def initialize():
    """
    Logging into Sophos and Zabbix with data passed by
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
    About every hour the Sophos token expires.
    Check if the token is expired
    every 5 minutes.
    In that case re-do the login and relaunch the thread.
    :return:
    """
    sleep(250)
    while True:
        if cfg.token_expired:
            logging.info('Requested new token')
            initialize()
            cfg.token_expired = False
            start()
        sleep(300)


if __name__ == '__main__':
    logging.info("MiddleMan started")
    initialize()
    start()
    re_login()
