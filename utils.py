import urllib, json, requests, random, sys
import logging
import jwt
from datetime import datetime, timedelta

from cloudfront import CloudFrontUtil

from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import ExpiredSignatureError
from error_handler import SystemFailureException, AccessDeniedException
from cache import ttl_cache

logger = logging.getLogger()

@ttl_cache(ttl = 3600)
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

@ttl_cache(ttl = 3600)
def get_certs(url):
  resp = urllib.request.urlopen(url).read().decode()
  data = json.loads(resp)["keys"]
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
  public_key = ""
  # find the key
  for key in key_set:
    if key["kid"] == headers["kid"]:
      public_key = RSAAlgorithm.from_jwk(json.dumps(key))
  if public_key == "":
    raise SystemFailureException("Key with kid not found")
  try:
    decoded = jwt.decode(
      token,
      public_key,
      algorithms=[headers["alg"]],
      audience=aud,
      leeway = 5
    )
    return decoded
  except ExpiredSignatureError as e:
    raise AccessDeniedException("Signature is not valid")

def gen_signed_cookie(key_id, private_key, resource, duration):
  """
  Creates signed cookie to be sent to cloudfront
  """
  expire_at = datetime.now() + timedelta(seconds=int(duration))
  cfu = CloudFrontUtil(private_key, key_id)
  cookies = cfu.generate_signed_cookies(resource, expire_at)

  # add expires cookie
  cookies["CloudFront-Expires"] = str(int(expire_at.timestamp()))

  logger.info(f"gen_signed_cookie: cookies: {cookies}")
  return cookies