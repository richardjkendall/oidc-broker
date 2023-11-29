import urllib, json, requests, random, sys
import logging
import jwt
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import ExpiredSignatureError

logger = logging.getLogger()


def get_wkc(host, realm):
  WKC_URL = "https://{host}/auth/realms/{realm}/.well-known/openid-configuration"
  url = WKC_URL.format(
    host=host,
    realm=realm
  )
  logger.info(f"get_wkc: url is {url}")
  resp = urllib.request.urlopen(url).read().decode()
  data = json.loads(resp)
  logger.info("get_wkc: got config", data)
  return data

def build_url(base, *args, **kwargs):
  url = base + "?"
  for key, value in kwargs.items():
    url = url + "{k}={v}&".format(k=key, v=value)
  return url[:-1]

def post_to_url(url, **kwargs):
  r = requests.post(url, data=kwargs)
  return r.content

def get_aurl(host, realm, client_id, redirect_uri, state):
  wkc_data = get_wkc(
    host=host,
    realm=realm
  )
  aurl = build_url(
    base=wkc_data["authorization_endpoint"],
    client_id=client_id,
    response_type="code",
    redirect_uri=redirect_uri,
    state=state
  )
  return aurl

def get_rand_string(number_of_characters):
  chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  rnd = random.SystemRandom()
  out = ""
  for d in range(number_of_characters):
      i = rnd.randint(0, sys.maxsize)
      i = i % len(chars)
      out = out + chars[i:i+1]
  return out

def validate_jwt(token, key_set, aud):
  headers = jwt.get_unverified_header(token)
  #public_key