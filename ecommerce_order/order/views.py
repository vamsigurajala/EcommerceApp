from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from .models import Order, OrderItems
from rest_framework.views import APIView
from rest_framework import views, serializers, status
from django.shortcuts import render , get_object_or_404
from rest_framework.response import  Response
from .serializers import OrderSerializer, OrderItemsSerializer
import requests
from datetime import datetime
import json
from orderservice.settings import user_url, product_url, cart_url, order_url, review_url
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.utils import timezone
import json

from django.views.decorators.http import require_GET
from .models import Order, OrderItems




# Create your views here.

class OrderAPIVew(views.APIView):

    def get(self, request):

        # Get the order with the specified order_id from the database
        order = Order.objects.filter(order_id=request.query_params.get('order_id')).first()
        serializer = OrderSerializer(order)
        return Response(serializer.data)
    

    def post(self, request):
        user_response = requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES).json()
        user_id=user_response["user_id"]

        # Create a new order with the retrieved user ID
        serializer = OrderSerializer(data={
            'user_id':user_id, 
        })

        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    



class OrderItemsAPIView(views.APIView):

    def get(self,request):
        
        # Get all the order items for the specified order ID from the database
        order_items = OrderItems.objects.filter(order_id = request.query_params.get('order_id')).all()
        serializer = OrderItemsSerializer(order_items, many = True)
        return Response(serializer.data)

    def post(self, request):

        # Get the order with the specified ID from the database
        order=Order.objects.filter(order_id=request.query_params.get('order_id')).first()
        if not order:
            return Response({'error':'order not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Retrieve the product ID from the ProductAPIView using a GET request
        product_id = requests.get(f'{product_url}/api/productview/{product_id}/').json()

        if not product_id:
            return Response({'error':'product not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Create a new order item with the retrieved data and save it to the database
        order_item_data = {
            'order_id': order.order_id,
            'product_id': product_id,
            'quantity': request.data.get('quantity', 1),
            'price': product_id['price'],
            'discount': product_id.get('discount',0)
        }
        serializer = OrderItemsSerializer(data=order_item_data)
        serializer.is_valid(raise_exception=True)
        print(serializer)
        serializer.save()
        # Update the total amount of the order
        order.total_amount += (product_id['price'] - product_id['discount']) * order_item_data['quantity']
        order.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)




class PlaceOrderView(APIView):
    def post(self, request):
        # Decode payload (form or raw JSON)
        raw = request.POST.get('order') or request.body
        try:
            orders_data = json.loads(raw) if isinstance(raw, (bytes, str)) else {}
        except Exception:
            return Response({'error': 'bad_order_payload'}, status=400)

        # Accept several shapes for the address id
        addr_id = None
        if isinstance(orders_data.get('address'), dict):
            addr_id = orders_data['address'].get('address_id') \
                   or orders_data['address'].get('id') \
                   or orders_data['address'].get('addressId')
        addr_id = addr_id or orders_data.get('address_id') \
                         or orders_data.get('selected_address_id') \
                         or orders_data.get('selectedAddressId')

        try:
            addr_id = int(addr_id)
        except Exception:
            return Response({'error': 'missing_or_invalid_address_id'}, status=400)

        # Compute total (authoritative on server)
        total = 0.0
        for it in (orders_data.get('items') or []):
            try:
                total += float(it.get('price', 0)) * int(it.get('quantity', 1))
            except Exception:
                pass
        total_amount = f"{total:.2f}"

        # Create order with the SELECTED address id
        order = Order.objects.create(
            user_id=int(orders_data.get('user_id')),
            address_id=addr_id,
            placed_time=datetime.now(),
            total_amount=total_amount,
            order_status="Placed",
        )
        print("[PlaceOrder] saved order:", order.order_id, "address_id=", addr_id)

                # >>> ADD: snapshot the chosen address onto the Order <<<
        def _fmt_addr(a: dict) -> str:
            if not a:
                return ""
            parts = [
                a.get('doorno') or a.get('door_no') or a.get('house_no') or a.get('house') or a.get('door'),
                a.get('street') or a.get('street1') or a.get('address1'),
                a.get('landmark') or a.get('address2') or a.get('street2'),
                a.get('city') or a.get('district'),
                a.get('state') or a.get('province'),
                a.get('pincode') or a.get('postal_code') or a.get('zip'),
            ]
            return ', '.join(str(p) for p in parts if p)

        def _addr_id_of(d: dict) -> str:
            # be tolerant to different key names
            for k in ('address_id', 'id', 'addressId', 'aid'):
                v = d.get(k)
                if v is not None:
                    return str(v)
            return ''

        chosen_addr_id = orders_data.get('address', {}).get('address_id')
        addr_obj = None
        try:
            ar = requests.get(f'{user_url}/api/getaddress/', cookies=request.COOKIES, timeout=8)
            if ar.ok:
                addresses = (ar.json() or {}).get('addresses', []) or []
                addr_obj = next((a for a in addresses if _addr_id_of(a) == str(chosen_addr_id)), None)
        except Exception:
            addr_obj = None

        if addr_obj:
            # These fields must exist on your Order model (add them if missing)
            order.recipient_name   = (
                addr_obj.get('customer_name') or addr_obj.get('username') or addr_obj.get('name')
                or f"{addr_obj.get('firstname','')} {addr_obj.get('lastname','')}".strip()
            )
            order.recipient_phone  = (
                addr_obj.get('customer_phone') or addr_obj.get('phone') or addr_obj.get('mobile') or ''
            )
            order.address_label    = addr_obj.get('address_type') or addr_obj.get('type') or 'Home'
            order.shipping_address = _fmt_addr(addr_obj)
            order.save(update_fields=['recipient_name','recipient_phone','address_label','shipping_address'])


        for cart_item in orders_data['items']:
            order_item = OrderItems(
                order_id_id = order.order_id,
                quantity = cart_item['quantity'],
                price = cart_item['price'],
                discount = 0,
                product_id=cart_item['product_id'],
            )
            order_item.save()

        return HttpResponse({'message': 'Order placed successfully'})
    
    def get(self, request):
        # PlaceOrderView.get (order service)
        user_id = requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES).json()['user_id']

        orders = (Order.objects
                .filter(user_id=user_id)
                .only('order_id', 'user_id', 'order_code', 'placed_time', 'address_id', 'order_status', 'total_amount')
                .order_by('-placed_time'))

        order_ids = [o.order_id for o in orders]
        items_qs = (OrderItems.objects
                    .filter(order_id_id__in=order_ids)
                    .only('order_id_id', 'product_id', 'quantity', 'price', 'discount'))

        # group items by order_id in one pass
        by_order = {}
        for it in items_qs:
            by_order.setdefault(it.order_id_id, []).append({
                'quantity': it.quantity,
                'product_id': it.product_id,
                'price': str(it.price),
                'discount': str(it.discount),
            })

        orderlist = []
        for o in orders:
            d = o.to_dict()
            d['order_items'] = by_order.get(o.order_id, [])
            orderlist.append(d)

        return Response({"orderlist": orderlist}, status=200)


        # print(data)
        return Response(data)
    

SUCCESS_STATUSES = {'Placed', 'On the way', 'Delivered'}
BAD_STATUSES     = {'Payment Failed', 'Order Not Placed', 'Cancelled', 'Returned'}

@require_GET
def has_purchased_internal(request):
    """
    Internal endpoint used by the Reviews service.
    Answer: {"has_purchased": true/false}
    True if this user has any non-failed order that contains the product.
    """
    uid = (request.GET.get('user_id') or '').strip()
    pid = (request.GET.get('product_id') or '').strip()
    if not uid or not pid:
        return JsonResponse({'has_purchased': False, 'error': 'missing params'}, status=400)

    # match your DB types (user_id is int; product_id stored as str)
    try:
        uid_i = int(uid)
    except Exception:
        return JsonResponse({'has_purchased': False, 'error': 'bad user_id'}, status=400)

    # Query the items table directly – avoids reverse related_name issues
    exists = OrderItems.objects.filter(
        order_id__user_id=uid_i
    ).exclude(
        order_id__order_status__in=BAD_STATUSES
    ).filter(
        product_id=str(pid)     # product_id column is a CharField in your code
    ).exists()

    return JsonResponse({'has_purchased': bool(exists)})


# orders/views.py
class PurchasedProductsView(APIView):
    def get(self, request):
        try:
            user_id = int(request.GET.get("user_id"))
        except (TypeError, ValueError):
            return Response({"error": "user_id required"}, status=400)

        qs = (OrderItems.objects
                .filter(order_id__user_id=user_id, order_id__order_status="Placed")
                .values_list('product_id', flat=True)
                .distinct())
        return Response({"product_ids": list(qs)}, status=200)
    

@csrf_exempt
@require_POST
def log_failed_order(request):
    try:
        payload = request.POST.get('order')
        data = json.loads(payload) if payload else {}
        print('[FAILED] payload keys:', list((data or {}).keys()))
    except Exception as e:
        print('[FAILED] bad_json:', e)
        return JsonResponse({'ok': False, 'error': 'bad_json'}, status=400)

    user_id    = data.get('user_id')
    address_id = data.get('address_id') or 0
    items      = data.get('items') or data.get('order_items') or []
    amount     = float(
        data.get('total_amount')
        or (data.get('summary') or {}).get('final_total')
        or 0
    )

    if not user_id or not items:
        return JsonResponse({'ok': False, 'error': 'missing_user_or_items'}, status=400)

    # 1) Create the failed order (signal assigns order_code)
    order = Order.objects.create(
        user_id=user_id,
        address_id=address_id,
        total_amount=amount,
        placed_time=timezone.now(),
        order_status='Payment Failed',
    )

    # 2) Attach items
    for it in items:
        OrderItems.objects.create(
            order_id_id=order.order_id,
            product_id=str(it.get('product_id')),
            quantity=int(it.get('quantity') or 1),
            price=float(it.get('price') or it.get('final_price') or it.get('amount') or 0),
            discount=0,
        )

    # 3) Pull the signal-assigned code into the instance (optional but nice)
    order.refresh_from_db(fields=['order_code'])

    print('[FAILED] created order_id:', order.pk, 'code:', order.order_code)
    return JsonResponse({'ok': True, 'order_id': order.pk, 'order_code': order.order_code})


## order/views.py
import pdfkit
from django.http import HttpResponse, Http404
from django.template.loader import render_to_string
from django.conf import settings

from .models import Order, OrderItems

PLATFORM_FEE_RS = getattr(settings, "PLATFORM_FEE_RS", 5.0)  # default ₹5

def invoice_pdf(request, order_id: int):
    # 1) Order
    order = Order.objects.filter(order_id=order_id).first()
    if not order:
        raise Http404("Order not found")

    # 2) Items
    items_qs = (OrderItems.objects
                .filter(order_id_id=order.order_id)
                .only("product_id", "quantity", "price", "discount"))

    items = [{
        "product_id": it.product_id,
        "quantity":    it.quantity,
        "price":       float(it.price),
        "discount":    float(it.discount),
        "total_price": float(it.price) * int(it.quantity),
    } for it in items_qs]

    # 3) Totals
    cart_total   = sum(x["total_price"] for x in items) if items else 0.0
    shipping_fee = 0.0 if cart_total == 0 else (0.0 if cart_total >= 1500 else 100.0)
    platform_fee = 0.0 if cart_total == 0 else float(PLATFORM_FEE_RS)

    summary = {
        "item_count":   len(items),
        "cart_total":   cart_total,
        "shipping_fee": shipping_fee,
        "platform_fee": platform_fee,
        "total_payable": cart_total + shipping_fee + platform_fee,
        "final_total":   float(order.total_amount) if order.total_amount else (cart_total + shipping_fee + platform_fee),
    }

    # 4) Template context (adjust fields if you store names/addresses)
    ctx = {
        "order": {
            "order_id":   order.order_id,
            "order_code": order.order_code,
            "placed_time": order.placed_time,
        },
        "items": items,
        "summary": summary,
        "billing_name":  "",  # fill if you store billing name
        "billing_addr":  "",  # fill if you store billing address
        "shipping_name": "",  # fill if you store recipient name
        "shipping_addr": "",  # fill if you store shipping address
    }

    html = render_to_string("invoice.html", ctx)

    # 5) Generate PDF (point to wkhtmltopdf if it’s not in PATH)
    # config = pdfkit.configuration(wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe")
    # pdf = pdfkit.from_string(html, False, configuration=config, options={ ... })

    pdf = pdfkit.from_string(html, False, options={
        "page-size": "A4",
        "encoding": "UTF-8",
        "enable-local-file-access": None,
        "margin-top": "10mm",
        "margin-bottom": "12mm",
        "margin-left": "10mm",
        "margin-right": "10mm",
    })

    resp = HttpResponse(pdf, content_type="application/pdf")
    resp["Content-Disposition"] = f'attachment; filename="INVOICE_{order_id}.pdf"'
    return resp
