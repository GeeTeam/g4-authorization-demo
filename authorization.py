import hmac
import time

def _gen_encryptstring():
    timestamp = str(int(time.time()))
    #产生随机数
    nonce = generate_rand_id(32)
    join_str = "".join(sorted((GT_ID, timestamp, nonce)))
    secret = bytes(GT_KEY, encoding="utf-8")
    message = bytes(join_str, encoding="utf-8")
    signature = hmac.new(secret, message, digestmod=hashlib.sha256).hexdigest()
    authorization = "gt_id=%s,nonce=%s,signature=%s,timestamp=%s" % (GT_ID, nonce, signature, timestamp)
    return authorization