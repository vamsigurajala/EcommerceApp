# payments_utils.py
from typing import List, Dict, Any

CARD_BRANDS = {"visa":"VISA","mastercard":"Mastercard","rupay":"RuPay","amex":"American Express","diners":"Diners","maestro":"Maestro","discover":"Discover"}
UPI_KEYS = {"upi","bhim","gpay","phonepe","paytm_upi","upi_intent"}

def _last4(x: Any) -> str:
    s = str(x or "").strip()
    return s[-4:] if s and s.isdigit() else s[-4:] if len(s)>=4 else ""

def normalize_payment_attempt(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Input: raw gateway row or your Payments service row.
    Output (uniform):
      {
        "mode": "UPI|Card|EMI|COD|Gift Card|Wallet|Netbanking|Other",
        "provider": "Razorpay / PayU / Stripe / Cashfree / ...",
        "brand": "VISA / HDFC / ... (optional)",
        "last4": "1234" (optional),
        "emi_tenure": 6 (optional),
        "upi_id": "name@okicici" (optional),
        "bank": "HDFC / ICICI..." (optional),
        "status": "success|failed|pending",
        "amount": float,
        "txn_id": "...",
        "raw": raw  # keep for debugging
      }
    """
    g = (raw.get("gateway") or raw.get("provider") or "").lower()
    provider = (raw.get("gateway") or raw.get("provider") or "").strip() or "Payments"

    status_lc = (raw.get("status") or raw.get("payment_status") or "").lower()
    if status_lc in ("captured","paid","success","succeeded","ok","completed"):
        status = "success"
    elif status_lc in ("failed","declined","error","cancelled"):
        status = "failed"
    else:
        status = "pending"

    # mode inference
    method = (raw.get("method") or raw.get("payment_method") or raw.get("mode") or "").lower()

    # COD?
    if method in ("cod","cash","cash_on_delivery") or raw.get("is_cod") is True:
        return {"mode":"COD","provider":"COD","status":status,"amount":float(raw.get("amount") or 0),"txn_id": raw.get("txn_id") or raw.get("id") or "", "raw":raw}

    # Gift cards / wallet
    if method in ("giftcard","gift_card","gv","voucher"):
        return {"mode":"Gift Card","provider":provider,"status":status,"amount":float(raw.get("amount") or 0),"txn_id": raw.get("txn_id") or raw.get("id") or "", "raw":raw}
    if method in ("wallet","paytm_wallet","phonepe_wallet","amazonpay","mobikwik"):
        return {"mode":"Wallet","provider":provider,"status":status,"amount":float(raw.get("amount") or 0),"txn_id": raw.get("txn_id") or raw.get("id") or "", "raw":raw}

    # UPI
    if method in UPI_KEYS or ("upi_vpa" in raw or "customer_vpa" in raw):
        return {
            "mode":"UPI","provider":provider,"status":status,
            "amount": float(raw.get("amount") or 0),
            "upi_id": raw.get("upi_vpa") or raw.get("customer_vpa") or raw.get("vpa") or "",
            "txn_id": raw.get("reference_id") or raw.get("txn_id") or raw.get("id") or "",
            "raw": raw,
        }

    # EMI (card emi)
    if method in ("emi","card_emi") or raw.get("emi_tenure"):
        brand = CARD_BRANDS.get((raw.get("card_brand") or "").lower(), raw.get("card_brand") or "")
        return {
            "mode":"EMI","provider":provider,"status":status,
            "amount": float(raw.get("amount") or 0),
            "brand": brand or raw.get("issuer") or "",
            "last4": _last4(raw.get("card_last4") or raw.get("last4")),
            "emi_tenure": int(raw.get("emi_tenure") or 0) or None,
            "txn_id": raw.get("reference_id") or raw.get("txn_id") or raw.get("id") or "",
            "raw": raw,
        }

    # Card (default)
    if method in ("card","debit_card","credit_card") or raw.get("card_last4") or raw.get("card_brand"):
        brand = CARD_BRANDS.get((raw.get("card_brand") or "").lower(), raw.get("card_brand") or "")
        return {
            "mode":"Card","provider":provider,"status":status,
            "amount": float(raw.get("amount") or 0),
            "brand": brand or raw.get("issuer") or "",
            "last4": _last4(raw.get("card_last4") or raw.get("last4")),
            "txn_id": raw.get("reference_id") or raw.get("txn_id") or raw.get("id") or "",
            "raw": raw,
        }

    # Netbanking
    if method in ("netbanking","nb","internet_banking") or raw.get("bank"):
        return {
            "mode":"Netbanking","provider":provider,"status":status,
            "amount": float(raw.get("amount") or 0),
            "bank": raw.get("bank") or raw.get("issuer") or "",
            "txn_id": raw.get("reference_id") or raw.get("txn_id") or raw.get("id") or "",
            "raw": raw,
        }

    # Fallback
    return {"mode":"Other","provider":provider,"status":status,"amount":float(raw.get("amount") or 0),"txn_id": raw.get("txn_id") or raw.get("id") or "", "raw":raw}


def headline_from_attempts(attempts: List[Dict[str,Any]]) -> str:
    """Pick a single headline for invoice like 'UPI', 'Card – VISA ****1234', 'EMI – HDFC ****1234 (6 mo)', 'Mixed payment'."""
    successful = [a for a in attempts if a["status"]=="success" and a.get("amount",0)>0]
    if not successful:
        # if COD pending
        for a in attempts:
            if a["mode"]=="COD":
                return "Cash on Delivery"
        return "Payment Pending"

    modes = {a["mode"] for a in successful}
    total_modes = len(modes)
    if total_modes > 1:
        return "Mixed payment"

    a = successful[0]
    if a["mode"]=="UPI":
        return "UPI"
    if a["mode"]=="Card":
        parts = ["Card"]
        if a.get("brand"): parts.append(f"– {a['brand']}")
        if a.get("last4"): parts.append(f" ****{a['last4']}")
        return " ".join(parts)
    if a["mode"]=="EMI":
        parts = ["Card EMI"]
        if a.get("brand"): parts.append(f"– {a['brand']}")
        if a.get("last4"): parts.append(f" ****{a['last4']}")
        if a.get("emi_tenure"): parts.append(f" ({a['emi_tenure']} mo)")
        return " ".join(parts)
    if a["mode"]=="Wallet": return "Wallet"
    if a["mode"]=="Gift Card": return "Gift Card"
    if a["mode"]=="Netbanking": return "Netbanking"
    if a["mode"]=="COD": return "Cash on Delivery"
    return a["mode"] or "Payment"
