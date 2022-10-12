import random
import string
import threading

from flask import Flask, render_template, redirect, url_for, request, session
from flask_cors import CORS, cross_origin

import middlecontroller
import sophos
import zabbix

app = Flask(__name__)
app.secret_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
CORS(app)


@app.route("/")
def index():
    if not session:
        return redirect(url_for('login'))
    return render_template('index.html')


@app.route("/stop")
def stop():
    if not session:
        return redirect(url_for('login'))

    for th in threading.enumerate():
        if th.name == 'middleman':
            if not middlecontroller.flag:
                return render_template('start.html', error='Thread already shutting down')
            middlecontroller.flag = False
            return render_template('start.html', message='Job stopped')

    return render_template('index.html', error='No thread running')


@app.route("/checktoken")
@cross_origin()
def check_token():
    return str(middlecontroller.tokenExpired)


@app.route("/start")
def start():
    if not session:
        return redirect(url_for('login'))

    for th in threading.enumerate():
        if th.name == 'middleman':
            return render_template('start.html', error='Thread already running')

    if middlecontroller.tokenExpired:
        return render_template('login.html', error='Token is expired, login again')

    middlecontroller.flag = True

    middlethread = threading.Thread(target=middlecontroller.hostcheck, name='middleman',
                                    args=[session['X-Region'], session['Authorization'], session['X-Tenant-ID'],
                                          session['Zabbix-auth'], session['Zabbix-ID']])

    middlethread.start()

    message = 'Thread started'
    return render_template('start.html', message=message)
    # return sophos.get_endpoint(session['X-Region'], session['Authorization'], session['X-Tenant-ID'],
    #                            '1d9fe137-13e0-4780-9bfe-b80a7a6e6d3f')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if session:
        return render_template('index.html', error='You are already logged in')

    if request.method == 'POST':
        sophos_id = request.form.get('sophosid')
        sophos_secret = request.form.get('sophosauth')
        zabbix_user = request.form.get('zabbixuser')
        zabbix_password = request.form.get('zabbixpass')

        slogin = sophos.login(sophos_id, sophos_secret)

        if slogin['errorCode'] != 'success':
            error = 'Sophos -> ' + slogin['errorCode']
            return render_template('login.html', error=error)

        whoami = sophos.whoami(slogin)
        token = slogin['token_type'].capitalize() + " " + slogin['access_token']

        zabbix_login = zabbix.login(zabbix_user, zabbix_password)
        if 'error' in zabbix_login:
            error = 'Zabbix -> ' + zabbix_login['error']['data']
            return render_template('login.html', error=error)

        session['Authorization'] = token
        session['X-Tenant-ID'] = whoami['id']
        session['X-Region'] = whoami['apiHosts']['dataRegion']
        session['Zabbix-auth'] = zabbix_login['result']
        session['Zabbix-ID'] = zabbix_login['id']

        return render_template('index.html', message='You are successfully logged in')

    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True)
