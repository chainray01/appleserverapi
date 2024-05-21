
# https://aviadas.com/blog/2015/06/18/verifying-x509-certificate-chain-of-trust-in-python/
import json
import time
import jwt
import requests
import logging
from OpenSSL import crypto
from jwt.utils import base64url_decode

logging.basicConfig(format='%(asctime)s - %(pathname)s[line:%(lineno)d] '
                           '- %(levelname)s: %(message)s', level=logging.DEBUG)

f = open("ca/AuthKey_QPBZD852F5.p8")
_authkey = f.read()
f.close()

f = open("ca/AppleRootCA-G3.pem")
_public_key = f.read()
f.close()

f = open("ca/AppleWWDRCAG6.pem")
_wwdr_ca = f.read()
f.close()

# https://developer.apple.com/documentation/appstoreserverapi/jwsdecodedheader
root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, _public_key.encode('utf-8'))
wwdr_cert = crypto.load_certificate(crypto.FILETYPE_PEM, _wwdr_ca.encode('utf-8'))

# JWT Header
header = {
    "alg": "ES256",
    "kid": "QPBZD852F0",
    "typ": "JWT"
}
# JWT Payload
payload = {
    "iss": "db1c0031-0e44-45d9-bbb0-4790cf785837",
    "aud": "appstoreconnect-v1",
    "iat": int(time.time()),
    "exp": int(time.time()) + 60 * 60,  # 60 minutes timestamp
    "nonce": "6edffe66-b482-11eb-8529-0242ac130001",
    "bid": "com.xxx.xxx"
}
token = jwt.encode(headers=header, payload=payload, key=_authkey, algorithm="ES256")
# 查询订阅
sub_url = "https://api.storekit.itunes.apple.com/inApps/v1/subscriptions/{originalTransactionId}"
# 订单信息
order_url = 'https://api.storekit.itunes.apple.com/inApps/v1/lookup/{orderId}'


def str2Cert(x):
    return '-----BEGIN CERTIFICATE-----\n' + x + '\n-----END CERTIFICATE-----'


def checkSignAndDecode(signedStr):
    header = jwt.get_unverified_header(signedStr)
    # cert_chain = list(map(str2Cert, header['x5c']))
    # logging.info(cert_chain)
    provided_certificates: [crypto.X509] = []
    certificate_names: [[bytes, bytes]] = []
    for cert_base64 in header['x5c']:
        another_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, base64url_decode(cert_base64))
        # To see the certificate chain by name, which corresponds to certs you can fetch:
        # https://www.apple.com/certificateauthority/
        #
        # Prints <X509Name object '/CN=Apple Root CA - G3/OU=Apple Certification Authority/O=Apple Inc./C=US'>:
        certificate_names.append(dict(another_cert.get_subject().get_components()))
        provided_certificates.append(another_cert)

    # Verify that the root & intermediate keys are what we expect from Apple:
    assert certificate_names[-1][b'CN'] == b'Apple Root CA - G3', f'Root cert changed: {certificate_names[-1]}'
    assert certificate_names[-2][b'OU'] == b'G6', f'Intermediate cert changed: {certificate_names[-2]}'
    assert provided_certificates[-2].digest('sha256') == wwdr_cert.digest('sha256')
    assert provided_certificates[-1].digest('sha256') == root_cert.digest('sha256')

    # Validate that the cert chain is cryptographically legit:
    store = crypto.X509Store()
    store.add_cert(root_cert)
    store.add_cert(wwdr_cert)
    # 验证证书链 主要是第一个证书 也可以逐级验证
    # logging.debug("cert:%s", provided_certificates[0].get_subject().get_components())
    # crypto.X509StoreContext(store, provided_certificates[0]).verify_certificate()
    for cert in provided_certificates[:-2]:
        try:
            logging.debug("cert:%s", cert.get_subject().get_components())
            crypto.X509StoreContext(store, cert).verify_certificate()
        except crypto.X509StoreContextError:
            logging.info("Invalid certificate chain in JWT: %s", signedStr)
            return None
        store.add_cert(cert)
    # store = crypto.X509Store()
    # for i in range(len(provided_certificates) - 2, -1, -1):
    #
    #     try:
    #         store.add_cert(provided_certificates[i + 1])
    #         cert = provided_certificates[i]
    #         logging.debug("cert:%s", cert.get_subject().get_components())
    #         crypto.X509StoreContext(store, cert).verify_certificate()
    #     except:
    #         logging.info("Invalid certificate chain in JWT: %s", signedStr)
    #         return None



    # Now that the cert is validated, we can use it to verify the actual signature
    # of the JWT. PyJWT does not understand this certificate if we pass it in, so
    # we have to get the cryptography library's version of the same key:
    cryptography_version_of_key = provided_certificates[0].get_pubkey().to_cryptography_key()
    try:
        return jwt.decode(signedStr, cryptography_version_of_key, algorithms=["ES256"])
    except Exception:
        logging.info("Problem validating Apple JWT")
        return None


def queryAutoRenew(url, queryheader):
    rs = requests.get(url, headers=queryheader)
    jsonStr = json.loads(rs.text)
    logging.info("resp:%s", jsonStr)
    status = jsonStr['data'][0]['lastTransactions'][0]['status']
    logging.info('status:%s', status)
    signedTransactionInfoStr = jsonStr['data'][0]['lastTransactions'][0]['signedTransactionInfo']
    transactionInfo = jwt.decode(signedTransactionInfoStr, options={"verify_signature": False})
    logging.info("transactionInfo:%s", transactionInfo)
    signedRenewalInfoStr = jsonStr['data'][0]['lastTransactions'][0]['signedRenewalInfo']
    #checkSignAndDecode(signedTransactionInfoStr)
    signedRenewalInfo = checkSignAndDecode(signedRenewalInfoStr)
    logging.info("signedRenewalInfo:%s", signedRenewalInfo)


def query_order(url, queryheader):
    rs = requests.get(url, headers=queryheader)
    jsonStr = json.loads(rs.text)
    logging.info("resp:%s", jsonStr)
    transactionInfo = checkSignAndDecode(jsonStr['signedTransactions'][0])
    logging.info("decode:%s", transactionInfo)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    queryheader = {
        "Authorization": f"Bearer {token}"
    }
    queryAutoRenew(sub_url.format(originalTransactionId=102001205569623), queryheader)
# query_order(order_url.format(orderId='MMHDSTMQ11'), queryheader)
