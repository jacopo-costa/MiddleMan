import datetime
import random
import string
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


@app.route("/stop")
def stop():
    for th in threading.enumerate():
        if th.name == 'middleman':
            if not gl.thread_flag:
                return jsonify(message='Thread already shutting down', code=400)
            gl.thread_flag = False
            return jsonify(message='Thread stopped', code=200)

    return jsonify(message='No thread running', code=400)


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


def initialize():
    cursor = gl.db.cursor(dictionary=True)
    cursor.execute('SELECT * FROM credentials')
    result = cursor.fetchone()

    sid = result['SophosID']
    secret = result['SophosSecret']
    zuser = result['ZabbixUser']
    zpass = result['ZabbixPass']
    cursor.close()

    slogin = sophos.login(sid, secret)
    whoami = sophos.whoami(slogin)
    token = slogin['token_type'].capitalize() + " " + slogin['access_token']

    zabbix_login = zabbix.login(zuser, zpass)

    gl.sophos_auth = token
    gl.sophos_id = whoami['id']
    gl.region = whoami['apiHosts']['dataRegion']
    gl.zabbix_auth = zabbix_login['result']
    gl.zabbix_id = zabbix_login['id']


def re_login():
    while True:
        if gl.token_expired:
            print('Richiesto nuovo token: ' + str(datetime.datetime.now()))
            # app.logger.info('Richiesto nuovo token: ' + str(datetime.datetime.now()))
            initialize()
            requests.get('http://localhost:5000/start')
            gl.token_expired = False
        sleep(300)


if __name__ == '__main__':
    initialize()

    tokenthread = threading.Thread(target=re_login, name='tokenthread')
    tokenthread.start()

    print('Server avviato: ' + str(datetime.datetime.now()))
    # app.logger.info('Server avviato: ' + str(datetime.datetime.now()))
    app.run(debug=True)
