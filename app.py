from flask import Flask, request


import base64
import gzip
import json
import logging
import os 
import requests
import datetime
import hashlib
import hmac


app = Flask(__name__)


WORKSPACE_ID = os.environ.get('workspaceId')
SHARED_KEY = os.environ.get('sharedKey')
API_KEY = os.environ.get('API_KEY')


if (WORKSPACE_ID is None or SHARED_KEY is None or API_KEY is None):
    raise Exception("Please add WORKSPACE_ID, SHARED_KEY and API_KEY to azure key vault/application settings of web app") 


LOG_TYPE = 'Log-Type'
HTTPS = 'https://'
AZURE_URL = '.ods.opinsights.azure.com'
AZURE_API_VERSION = '?api-version=2016-04-01'
RESOURCE = '/api/logs'
POST_METHOD = 'POST'
CONTENT_TYPE = 'application/json'
URI = "{}{}{}{}{}".format(HTTPS, WORKSPACE_ID, AZURE_URL, RESOURCE, AZURE_API_VERSION)
POOL = requests.Session()
POOL.mount(URI, requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=8))
FAILURE_RESPONSE = json.dumps({'success':False})
SUCCESS_RESPONSE = json.dumps({'success':True})
APPLICATION_JSON = {'ContentType':'application/json'}


class UnAuthorizedException(Exception):
    pass


class ProcessingException(Exception):
    pass


# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = "{}\n{}\n{}\n{}\n{}".format(method, str(content_length), content_type, x_headers, resource)
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization


def post(headers, body):
    response = POOL.post(URI, data=body, headers=headers)
    if not (200 <= response.status_code <= 299):
        try:
            resp_body = str(response.json())
        except json.JSONDecodeError:
            resp_body = response.text
        resp_headers = json.dumps(headers)
        failure_resp = "failure response details: {}{}{}".format(response.status_code, resp_body, resp_headers)
        raise ProcessingException("ProcessingException: {}".format(failure_resp))


# Build Auth and send request to the POST API
def post_data(customer_id, shared_key, body, log_type):
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, POST_METHOD, CONTENT_TYPE, RESOURCE)
    headers = {
        'content-type': CONTENT_TYPE,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    post(headers, body)


@app.route('/', methods=['POST'])
def func():
    auth_header = request.headers.get("authorization")
    if auth_header is None or not auth_header.startswith("ApiKey "):
        return FAILURE_RESPONSE, 401, APPLICATION_JSON

    api_key_sent = auth_header.split("ApiKey ")[1]
    if api_key_sent != API_KEY:
        logging.error("UnAuthorized ApiKey header mismatch")
        return FAILURE_RESPONSE, 401, APPLICATION_JSON

    log_type = request.headers.get(LOG_TYPE)
    if not log_type:
        logging.error("Missing Log-Type header")
        return FAILURE_RESPONSE, 400, APPLICATION_JSON

    body = request.get_data()
    
    try:
        decompressed = gzip.decompress(body)
        if not decompressed:
            logging.error("Empty body after decompression")
            return FAILURE_RESPONSE, 400, APPLICATION_JSON
        
        logging.debug("processed request auth")
        post_data(WORKSPACE_ID, SHARED_KEY, decompressed, log_type)
        
    except gzip.BadGzipFile:
        logging.error("Bad Gzip File")
        return FAILURE_RESPONSE, 400, APPLICATION_JSON
    except ProcessingException as e:
        logging.error("ProcessingException: %s", e)
        return FAILURE_RESPONSE, 500, APPLICATION_JSON 
    except Exception as e:
        logging.error("Exception: %s", e)
        return FAILURE_RESPONSE, 500, APPLICATION_JSON 
       
    return SUCCESS_RESPONSE, 200, APPLICATION_JSON 


@app.route('/health', methods=['GET'])
def health():
    return SUCCESS_RESPONSE, 200, APPLICATION_JSON 


if __name__ == '__main__':
   app.run()