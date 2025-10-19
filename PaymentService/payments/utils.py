# payments/utils.py
import time, random

def generate_txn_id() -> str:
    """
    Pure numbers. Format: yyyymmddHHMMSS + 6 random digits = 20 digits.
    Example: 20251010 145432 123456 -> "20251010145432123456"
    """
    now = time.strftime("%Y%m%d%H%M%S")   # 14 digits
    rnd = random.randint(0, 999999)       # 6 digits
    return f"{now}{rnd:06d}"

def make_txn_id(prefix="TX"):
    # 13-digit ms timestamp + 5 random digits = 18 digits; add 2-char prefix => length <= 20
    return f"{prefix}{int(time.time() * 1000):013d}{random.randint(0, 99999):05d}"