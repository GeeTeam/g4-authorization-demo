import hashlib
import hmac
import random
import string
import time

GT_ID = "xp9mzzxttrrjheg8jtojwskqzz64zq3j"  # Replace this by your owner GT_ID
GT_KEY = "h9yldjrzxaeiabtad0kb4ty5ivj7ehr1"  # Replace this by your GT_KEY


def _gen_encryptstring():
    timestamp = str(int(time.time()))
    chars = string.digits + string.ascii_lowercase
    nonce = "".join(random.choice(chars) for _ in range(32))
    join_str = "".join(sorted((GT_ID, timestamp, nonce)))
    secret = GT_KEY.encode('utf-8')
    message = join_str.encode('utf-8')
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    authorization = "gt_id={},nonce={},signature={},timestamp={}"
    return authorization.format(GT_ID, nonce, signature, timestamp)


if __name__ == "__main__":
    print(_gen_encryptstring())
