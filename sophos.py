from functools import wraps

import requests
from flask import jsonify, request, Blueprint
from flask_cors import cross_origin

url_token = "https://id.sophos.com/api/v2/oauth2/token"
url_id = "https://api.central.sophos.com/whoami/v1"
hidden_client_id = "d4c82aff-efd3-4ec8-a040-685434d5d690"
hidden_client_secret = \
    "5427d5c01745f0768d2bea887cd4f7c90bed805587edab1b4d3ac12949fe691c6961b5b1685a47d0f34d66d6733f89f59c09"

sophos = Blueprint('sophos', __name__)


def credentials_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        jwt = None
        id = None
        region_url = None

        if 'Authorization' in request.headers:
            jwt = request.headers['Authorization']

        if 'X-Tenant-ID' in request.headers:
            id = request.headers['X-Tenant-ID']

        if 'X-Region' in request.headers:
            region_url = request.headers['X-Region']

        if not jwt:
            return jsonify({'message': 'Missing Token'}), 401
        elif not id:
            return jsonify({'message': 'Missing Tenant ID'}), 401
        elif not region_url:
            return jsonify({'message': 'Missing Region data'}), 401

        current_user = {
            "jwt": jwt,
            "id": id,
            "data_region": region_url
        }

        return f(current_user, *args, **kwargs)

    return decorator


@sophos.route("/sophos/login", methods=['POST'])
def sophos_login():
    login = request.json
    if not login:
        return jsonify({"message": "No client id or secret sent"})

    data = "grant_type=client_credentials&client_id=" + login['client_id'] + "&client_secret=" + login[
        'client_secret'] + "&scope=token"
    return requests.post(url_token, headers={"Content-Type": "application/x-www-form-urlencoded"}, data=data).json()


@sophos.route("/sophos/whoami", methods=['GET'])
def whoami():
    data = request.json
    if not data:
        return jsonify({"message": "No token sent"})

    if not "Authorization" in data:
        return jsonify({'message': 'Invalid JSON'}), 401
    authorization = data['token_type'] + " " + data['Authorization']

    return requests.get(url_id, headers={"Authorization": authorization}).json()


@sophos.route("/sophos/getendpoints", methods=['GET', 'OPTIONS'])
@cross_origin()
@credentials_required
def get_endpoints(current_user):
    if request.args:
        string = ""
        for key, value in request.args:
            string = string + str(key) + "=" + str(value) + "&"
        string = string[:-1]
        return requests.get(current_user['data_region'] + "/endpoint/v1/endpoints?" + string,
                            headers={
                                "Authorization": current_user['jwt'],
                                "X-Tenant-ID": current_user['id']
                            }).json()

    return requests.get(current_user['data_region'] + "/endpoint/v1/endpoints",
                        headers={
                            "Authorization": current_user['jwt'],
                            "X-Tenant-ID": current_user['id']
                        }).json()


@sophos.route("/sophos/getalerts", methods=['GET', 'OPTIONS'])
@cross_origin()
@credentials_required
def get_alerts(current_user):
    if request.args:
        string = ""
        for key, value in request.args:
            string = string + str(key) + "=" + str(value) + "&"
        string = string[:-1]
        return requests.get(current_user['data_region'] + "/common/v1/alerts?" + string,
                            headers={
                                "Authorization": current_user['jwt'],
                                "X-Tenant-ID": current_user['id']
                            }).json()

    return requests.get(current_user['data_region'] + "/common/v1/alerts",
                        headers={
                            "Authorization": current_user['jwt'],
                            "X-Tenant-ID": current_user['id']
                        }).json()


@sophos.route("/sophos/getroles", methods=['GET', 'OPTIONS'])
@cross_origin()
@credentials_required
def get_roles(current_user):
    if request.args:
        string = ""
        for key, value in request.args:
            string = string + str(key) + "=" + str(value) + "&"
        string = string[:-1]
        return requests.get(current_user['data_region'] + "/common/v1/roles?" + string,
                            headers={
                                "Authorization": current_user['jwt'],
                                "X-Tenant-ID": current_user['id']
                            }).json()

    return requests.get(current_user['data_region'] + "/common/v1/roles",
                        headers={
                            "Authorization": current_user['jwt'],
                            "X-Tenant-ID": current_user['id']
                        }).json()


@sophos.route("/sophos/gethealth", methods=['GET', 'OPTIONS'])
@cross_origin()
@credentials_required
def get_health(current_user):
    return requests.get(current_user['data_region'] + "/account-health-check/v1/health-check",
                        headers={
                            "Authorization": current_user['jwt'],
                            "X-Tenant-ID": current_user['id']
                        }).json()


@sophos.route("/test/headers", methods=['POST', 'OPTIONS'])
@cross_origin()
@credentials_required
def test_headers(current_user):
    print(request.json)
    return "Hello Headers"
