import logging
import json
import boto3
import base64
from hashlib import sha256

import awsgi
from flask_cors import CORS
from flask import Flask, jsonify, make_response, request, redirect
from error_handler import error_handler, BadRequestException, ResourceNotFoundException, AccessDeniedException
from utils import get_aurl, get_rand_string, post_to_url, get_wkc, validate_jwt, get_certs, gen_signed_cookie

# fix for compatability with AWS lambda logging
if len(logging.getLogger().handlers) > 0:
  logging.getLogger().setLevel(logging.INFO)
else:
  logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] (%(threadName)-10s) %(message)s')
logger = logging.getLogger()
logger.info("Starting...")

app = Flask(__name__)
CORS(app)

dynamodb = boto3.resource("dynamodb")
ssm = boto3.client("ssm")
table = dynamodb.Table("login_dev")

def get_ssm_secret(param_name):
  parameter = ssm.get_parameter(Name=param_name, WithDecryption=True)
  return parameter['Parameter']['Value']

def get_site(sitename):
  response = table.get_item(
    Key={
      "site": sitename
    }
  )
  if "Item" not in response:
    raise ResourceNotFoundException("Site not found")
  else:
    return response["Item"]

def success_json_response(payload):
  """
  Turns payload into a JSON HTTP200 response
  """
  response = make_response(jsonify(payload), 200)
  response.headers["Content-type"] = "application/json"
  return response

@app.route("/process", methods=["GET"])
@error_handler
def process():
  """
  Processes a login callback from OIDC provider
  """
  # need to process and validate the state first
  state = request.args.get("state")
  if state == None:
    raise BadRequestException("No state in request")
  state = base64.b64decode(state).decode("utf-8")
  state = json.loads(state)
  if "site" not in state:
    raise BadRequestException("No site specified in state")
  sitename = state["site"]
  source_url = state["source_url"]
  request_id = state["request_id"]
  site = get_site(sitename)
  # need to validate the hash in the state
  hash_source = site["state_secret"] + sitename + source_url + request_id
  hash_hash = sha256(hash_source.encode("utf-8")).hexdigest()
  if hash_hash != state["hash"]:
    raise AccessDeniedException("Hash mismatch")
  # hash is matched
  logger.info("process: hash is matched")
  # get code from URL
  code = request.args.get("code")
  if code == None:
    raise BadRequestException("Code missing from request")
  # swap authorisation code for tokens
  redirect_uri = "{}://{}/process".format(request.scheme, request.host)
  wkc_data = get_wkc(
    host = site["oidc_host"],
    realm = site["oidc_realm"]
  )
  resp = post_to_url(
    url=wkc_data["token_endpoint"],
    grant_type="authorization_code",
    client_id=site["oidc_client_id"],
    client_secret=site["oidc_client_secret"],
    code=code,
    redirect_uri=redirect_uri
  )
  resp = json.loads(resp)
  # need to validate the JWT signature
  keys = get_certs(
    url=wkc_data["jwks_uri"]
  )
  validate_jwt(
    token=resp["access_token"],
    key_set=keys,
    aud=sitename
  )
  # we need to get the private key from ssm
  signing_key = get_ssm_secret(site["signing_key"])
  # then need to generate the signed cookie and send back to CF process step
  cookies = gen_signed_cookie(
    key_id = site["key_id"],
    private_key = signing_key,
    resource = site["resource"],
    duration = site["cookie_duration"]
  )
  # hash the secret and ID
  token = sha256(site["state_secret"].encode("utf-8"))
  token.update(request_id.encode("utf-8"))
  to_send_to_site = {
    "cookies": cookies,
    "source_url": state["source_url"],
    "token": base64.b64encode(token.digest()).decode(),
    "request_id": request_id
  }
  to_send_to_site_b64 = base64.b64encode(json.dumps(to_send_to_site).encode("utf-8")).decode("utf-8")
  target_url = site["redirect_to"] + "?state=" + to_send_to_site_b64
  return redirect(target_url, 302)

@app.route("/login", methods=["GET"])
@error_handler
def start():
  """
  Starts the login process for a given site
  """
  sitename = request.args.get("site")
  redirect_uri = "{}://{}/process".format(request.scheme, request.host)
  if sitename != None:
    site = get_site(sitename)
    source_url = "/"
    requestid = request.args.get("id")
    if request.args.get("src") != None:
      source_url = request.args.get("src")
    if requestid == None:
      raise BadRequestException("No request ID")
    hash_source = site["state_secret"] + sitename + source_url + requestid
    state_source = {
      "source_url": source_url,
      "site": sitename,
      "request_id": requestid,
      "hash": sha256(hash_source.encode("utf-8")).hexdigest(),
      "nonce": get_rand_string(10)
    }
    state = base64.b64encode(json.dumps(state_source).encode("utf-8")).decode("utf-8")
    aurl = get_aurl(
      host = site["oidc_host"],
      realm = site["oidc_realm"],
      client_id = site["oidc_client_id"],
      redirect_uri = redirect_uri,
      state = state
    )
    return redirect(aurl, code = 302)
  else:
    raise BadRequestException("Request must be JSON")

@app.before_request
def log_request():
  logger.info("before_request: Request headers: %s", request.headers)
  logger.info("before_request: Request body: %s", request.get_data().decode("utf-8"))

@app.after_request
def log_response(response):
  logger.info("after_request: Response body: %s", response.get_data().decode("utf-8"))
  return response

def lambda_handler(event, context):
  logger.info("lambda_handler: new request, event %s", json.dumps(event))
  return awsgi.response(app, event, context, base64_content_types={"image/png"})

if __name__ == "__main__":
  logger.info("Starting as main")
  app.run(debug=True, port=5001, host="0.0.0.0", threaded=True)