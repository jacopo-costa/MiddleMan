import logging
import os
import random
import string
import sys
import threading
from time import sleep

from flask import Flask, jsonify
from flask_cors import CORS, cross_origin

import config as cfg
import middlecontroller
import sophos
import zabbix

app = Flask(__name__)
app.secret_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
CORS(app)

# Logging config with timestamp
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                    level=logging.INFO,
                    datefmt='%d-%m-%Y %H:%M:%S')

# Disable HTTP status log
logging.getLogger('werkzeug').disabled = True


@app.route("/status")
@cross_origin()
def check_thread():
    """
    Check if the thread is running by looking at its flag
    :return: Value of the thread flag as string
    """
    return str(cfg.thread_flag)


def start():
    """
    Start the thread with the check routine.
    If the thread is already running return an error.
    :return: Status message as JSON
    """
    # for th in threading.enumerate():
    #     if th.name == 'middleman' and cfg.thread_flag:
    #         return jsonify(message='Thread already running', code=400)
    #     elif th.name == 'middleman' and not cfg.thread_flag:
    #         cfg.thread_flag = True
    #         return jsonify(message='Thread started', code=200)

    cfg.thread_flag = True

    middlethread = threading.Thread(target=middlecontroller.routine, name='middleman')

    middlethread.start()


def stop():
    """
    Stop the routine thread.
    If there is no thread running return an error.
    :return: Status message as JSON
    """
    for th in threading.enumerate():
        if th.name == 'middleman':
            if not cfg.thread_flag:
                return jsonify(message='Thread already shutting down', code=400)
            cfg.thread_flag = False
            return jsonify(message='Thread stopped', code=200)

    return jsonify(message='No thread running', code=400)


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
    Secondary thread that check if the Sophos token is expired
    every 5 minutes.
    In that case re-do the login and relaunch the thread.
    :return:
    """
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
    tokenthread = threading.Thread(target=re_login, name='tokenthread')
    tokenthread.start()
    start()
    app.run(host='0.0.0.0', port=5000)
