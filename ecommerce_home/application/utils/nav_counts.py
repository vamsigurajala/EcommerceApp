# application/utils/nav_counts.py

def _unique_ids(items, key='product_id'):
    ids = set()
    for it in items or []:
        if isinstance(it, dict):
            pid = it.get(key) or it.get('product') or it.get('id')
        else:
            pid = getattr(it, key, None) or getattr(it, 'id', None)
        if pid:
            ids.add(pid)
    return len(ids)

def nav_counts(request):
    """
    Reads from the real snapshot session keys used by your app.
    """
    cart_items = request.session.get('__cart_snapshot__', [])
    wishlist_items = request.session.get('__wishlist_snapshot__', [])

    cart_count = _unique_ids(cart_items, 'product_id')
    wishlist_count = _unique_ids(wishlist_items, 'product_id')

    # DEBUG: show in console so you can confirm it's working
    #print(f"[CTX] cart={cart_count} wl={wishlist_count} keys={list(request.session.keys())}")

    return {
        'cart_count': cart_count,
        'wishlist_count': wishlist_count,
    }
