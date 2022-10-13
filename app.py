import datetime
import logging
import os
import random
import string
import sys
import threading
from time import sleep

import requests
from flask import Flask, jsonify
from flask_cors import CORS, cross_origin

import global_vars as gl
import middlecontroller
import sophos
import zabbix

app = Flask(__name__)
app.secret_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
CORS(app)

logging.basicConfig(level=logging.INFO)


@app.route("/")
def index():
    zid = gl.zabbix_id
    zauth = gl.zabbix_auth
    sid = gl.sophos_id
    sauth = gl.sophos_auth
    reg = gl.region

    return jsonify(ZabbixID=zid,
                   ZabbixAuth=zauth,
                   SophosID=sid,
                   SophosAuth=sauth,
                   Region=reg)


@app.route("/status")
@cross_origin()
def check_thread():
    return str(gl.thread_flag)


@app.route("/start")
def start():
    for th in threading.enumerate():
        if th.name == 'middleman' and gl.thread_flag:
            return jsonify(message='Thread already running', code=400)
        elif th.name == 'middleman' and not gl.thread_flag:
            gl.thread_flag = True
            return jsonify(message='Thread started', code=200)

    gl.thread_flag = True

    middlethread = threading.Thread(target=middlecontroller.routine, name='middleman')

    middlethread.start()

    return jsonify(message='Thread started', code=200)


@app.route("/stop")
def stop():
    for th in threading.enumerate():
        if th.name == 'middleman':
            if not gl.thread_flag:
                return jsonify(message='Thread already shutting down', code=400)
            gl.thread_flag = False
            return jsonify(message='Thread stopped', code=200)

    return jsonify(message='No thread running', code=400)


def initialize():
    try:
        sid = os.environ['SOPHOS_ID']
        secret = os.environ['SOPHOS_SECRET']
        zuser = os.environ['ZABBIX_USER']
        zpass = os.environ['ZABBIX_PASS']
    except KeyError:
        logging.error("Environment variables not set")
        sys.exit(1)

    slogin = sophos.login(sid, secret)
    whoami = sophos.whoami(slogin)
    token = slogin['token_type'].capitalize() + " " + slogin['access_token']

    zabbix_login = zabbix.login(zuser, zpass)

    gl.sophos_auth = token
    gl.sophos_id = whoami['id']
    gl.region = whoami['apiHosts']['dataRegion']
    gl.zabbix_auth = zabbix_login['result']
    gl.zabbix_id = zabbix_login['id']

    tokenthread = threading.Thread(target=re_login, name='tokenthread')
    tokenthread.start()


def re_login():
    while True:
        if gl.token_expired:
            logging.info('Richiesto nuovo token: ' + str(datetime.datetime.now()))
            initialize()
            requests.get('http://localhost:5000/start')
            gl.token_expired = False
        sleep(300)


if __name__ == '__main__':
    initialize()
    logging.info("Server avviato")
    app.run(host='0.0.0.0', port=5000)
