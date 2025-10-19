# orders/utils.py
import hashlib
from django.utils import timezone

# digits only, easy to read (12 digits)
def _encode_digits(pk: int, salt: str = "ord-v1", length: int = 12) -> str:
    h = hashlib.sha1(f"{salt}-{pk}".encode("utf-8")).hexdigest()
    # turn hex → big int → digits, then take <length> digits
    n = int(h, 16)
    out = []
    for _ in range(length):
        n, r = divmod(n, 10)
        out.append(str(r))
    return "".join(reversed(out))

def gen_order_code(pk: int, placed_time=None) -> str:
    """
    NCOD + 12 digits (numbers only).
    Use YYMMDD + last 6 digits of pk (zero-padded) => 6+6 = 12 digits.
    Deterministic and unique for pk<1,000,000.
    """
    dt = placed_time or timezone.now()
    date_part = dt.strftime("%y%m%d")          # 6 digits, e.g. 251010
    seq = int(pk) % 1_000_000                  # 0..999999
    return f"NCOD{date_part}{seq:06d}"    