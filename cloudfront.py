"""
generate signed urls or cookies for AWS CloudFront

pip install botocore rsa requests
"""
from datetime import datetime, timedelta
import functools
from urllib.parse import urlsplit
from os.path import exists

from botocore.signers import CloudFrontSigner
import requests
import rsa


class CloudFrontUtil:
    def __init__(self, private_key_path: str, key_id: str):
        """
        :param private_key_path: str, the path of private key which generated by openssl command line
        :param key_id: str, CloudFront -> Key management -> Public keys
        """
        self.key_id = key_id

        priv_key = ""

        if exists(private_key_path):
            with open(private_key_path, 'rb') as fp:
                priv_key = rsa.PrivateKey.load_pkcs1(fp.read())
        else:
            priv_key = rsa.PrivateKey.load_pkcs1(bytes(private_key_path, "utf-8"))

        # NOTE: CloudFront use RSA-SHA1 for signing URLs or cookies
        self.rsa_signer = functools.partial(
            rsa.sign, priv_key=priv_key, hash_method='SHA-1'
        )
        self.cf_signer = CloudFrontSigner(key_id, self.rsa_signer)

    def generate_presigned_url(self, url: str, expire_at: datetime) -> str:
        # Create a signed url that will be valid until the specfic expiry date
        # provided using a canned policy.
        return self.cf_signer.generate_presigned_url(url, date_less_than=expire_at)

    def generate_signed_cookies(self, url: str, expire_at: datetime) -> str:
        policy = self.cf_signer.build_policy(url, expire_at).encode('utf8')
        policy_64 = self.cf_signer._url_b64encode(policy).decode('utf8')

        signature = self.rsa_signer(policy)
        signature_64 = self.cf_signer._url_b64encode(signature).decode('utf8')
        return {
            "CloudFront-Policy": policy_64,
            "CloudFront-Signature": signature_64,
            "CloudFront-Key-Pair-Id": self.key_id,
        }

if __name__ == '__main__':
    private_key_path = './key.pem'  # generated by openssl command
    key_id = 'blah'  # CloudFront -> Key management -> Public keys, the value of `ID` field
    url = 'scheme://host/path'  # your file's cdn url
    expire_at = datetime.now() + timedelta(hours=1)

    cfu = CloudFrontUtil(private_key_path, key_id)

    obj_key = urlsplit(url).path
    
    # signed cookies
    signed_cookies = cfu.generate_signed_cookies(f"{url}*", expire_at)
    r = requests.get(url, cookies=signed_cookies)
    print(f'using signed cookie: {obj_key}, {r.status_code}, {r.content}')

    print(f"cookies {signed_cookies}")

    # signed url
    #signed_url = cfu.generate_presigned_url(url, expire_at)
    #r = requests.get(signed_url)
    #print(f'\nusing signed url: {obj_key}, {r.status_code}, {r.content}')