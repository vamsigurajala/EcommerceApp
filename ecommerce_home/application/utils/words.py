# utils/words.py

ONES = ["","one","two","three","four","five","six","seven","eight","nine",
        "ten","eleven","twelve","thirteen","fourteen","fifteen","sixteen","seventeen","eighteen","nineteen"]
TENS = ["","","twenty","thirty","forty","fifty","sixty","seventy","eighty","ninety"]

def _two(n):
    if n == 0: return ""
    if n < 20: return ONES[n]
    t,u = divmod(n,10)
    return TENS[t] + (f" {ONES[u]}" if u else "")

def _three(n, use_and):
    h, r = divmod(n,100)
    if h and r:
        return f"{ONES[h]} hundred{' and ' if use_and else ' '}{_two(r)}"
    if h:
        return f"{ONES[h]} hundred"
    return _two(r)

def int_to_words_indian(n: int, use_and: bool = True) -> str:
    if n == 0: return "zero"
    parts = []
    crore, n = divmod(n, 10_000_000)
    lakh,  n = divmod(n, 100_000)
    thousand, n = divmod(n, 1000)
    hundred_block = n

    if crore:   parts.append(_two(crore) + " crore")
    if lakh:    parts.append(_two(lakh) + " lakh")
    if thousand:parts.append(_two(thousand) + " thousand")
    if hundred_block: parts.append(_three(hundred_block, use_and))

    # Join with spaces; when use_and=True we already inserted “and” inside _three for sub-100
    return " ".join(p for p in parts if p).strip()

def amount_in_words_rupees(amount, use_and=True):
    # amount can be Decimal/float/int; we’ll ignore paise in words (common for invoices)
    from decimal import Decimal, ROUND_HALF_UP
    amt = Decimal(str(amount)).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    return int_to_words_indian(int(amt), use_and=use_and).title()
