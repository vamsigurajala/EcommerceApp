# utils/payments.py (or inside views.py if you prefer)
from register.settings import user_url, product_url, cart_url, order_url, review_url, payment_url
import requests


def _card_tail(num: str) -> str:
    d = "".join(ch for ch in str(num or "") if ch.isdigit())
    return f"••{d[-4:]}" if len(d) >= 4 else "••••"

def _label_for_attempt(a: dict) -> str:
    m = (a.get("method") or a.get("payment_method") or "").lower()
    net = (a.get("network") or a.get("brand") or a.get("gateway") or "").title()
    status = (a.get("status") or "").lower()

    if m in {"cod","cash_on_delivery","pay_on_delivery"}:
        return "Cash on Delivery"
    if m in {"upi"}:
        handle = a.get("upi_id") or a.get("vpa")
        return f"UPI ({handle})" if handle else "UPI"
    if m in {"card","credit_card","debit_card"}:
        brand = (a.get("brand") or a.get("scheme") or "Card").title()
        last4 = a.get("last4") or _card_tail(a.get("card_number"))
        return f"{brand} {_card_tail(last4)}"
    if m in {"netbanking","net_banking","bank"}:
        bank = a.get("bank") or a.get("issuer")
        return f"NetBanking ({bank})" if bank else "NetBanking"
    if m in {"wallet"}:
        w = a.get("wallet") or net or "Wallet"
        return w
    if m in {"emi"}:
        brand = (a.get("brand") or "Card").title()
        months = a.get("tenure") or a.get("months")
        if months:
            return f"EMI ({brand}, {months} months)"
        return f"EMI ({brand})"

    # Unknown -> try network/gateway name
    return net or "Payment"

def get_payment_breakdown(order_id: int, request):
    """
    Returns a dict that works for old & new orders:
      {
        'headline': 'UPI (user@bank)' / 'Cash on Delivery' / 'Visa ••1234' / 'Payment',
        'attempts': [...raw attempts...],
        'paid_amount': 151802.00
      }
    """
    attempts = []
    paid_amount = None
    headline = "Payment"

    # 1) Try Payments service (preferred)
    try:
        r = requests.get(
            f"{payment_url}/api/orders/payments/",
            params={"order_id": order_id},
            cookies=request.COOKIES,
            timeout=8,
        )
        if r.ok:
            data = r.json() or {}
            attempts = data.get("attempts") or data.get("payments") or []
            # pick a successful attempt if present, else last one
            winner = next((a for a in attempts if (a.get("status") or "").lower() in {"paid","captured","success"}), None) \
                     or (attempts[-1] if attempts else None)
            if winner:
                headline = _label_for_attempt(winner)
                paid_amount = winner.get("amount") or winner.get("captured_amount")
    except Exception:
        pass

    # 2) Fall back to the order snapshot (older orders)
    # Look for typical flags/fields you might already store
    if headline == "Payment":
        o = request._order_snapshot if hasattr(request, "_order_snapshot") else None  # optional hook
        # or pass the 'order' dict into this function and use it directly
        # e.g., def get_payment_breakdown(order, request)
        # and then consult order.get('cod'), order.get('payment_mode'), etc.
    # If you have order dict here, do:
    # mode = (order.get("payment_mode") or order.get("pay_method") or "").lower()
    # cod_flag = order.get("is_cod") or order.get("cod")
    # if cod_flag or mode=="cod": headline = "Cash on Delivery"
    # elif mode: headline = mode.upper()

    # If amount still None, use order total payable as best-effort
    try:
        if paid_amount is None:
            from decimal import Decimal
            paid_amount = Decimal(str(request._paid_amount_hint))  # optional hook
    except Exception:
        paid_amount = None

    return {"headline": headline, "attempts": attempts, "paid_amount": paid_amount}
