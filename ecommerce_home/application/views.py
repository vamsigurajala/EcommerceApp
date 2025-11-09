from django.http import HttpResponse, request,HttpResponseBadRequest
from django.shortcuts import redirect, render
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from .serializers import UserSerializer, AddressSerializer
from .models import User, Address
from django.conf import settings 
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
import requests
from rest_framework.decorators import api_view
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST
from rest_framework import views, status, generics
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
import json
import jwt
from datetime import datetime, timedelta, timezone
from register.settings import user_url, product_url, cart_url, order_url, review_url, payment_url
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt 
from django.views.decorators.http import require_POST, require_GET, require_http_methods 
from django.contrib import messages
from django.http import JsonResponse, HttpResponseNotFound
from urllib.parse import urljoin
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from urllib.parse import urlencode
from typing import List, Dict
from django.urls import reverse
import uuid as py_uuid
import uuid
from django.core.paginator import Paginator
from django.shortcuts import render
import requests
import random
import hashlib
from .utils.auth import get_user_from_request
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from .utils.payment_utils import normalize_payment_attempt, headline_from_attempts
from .utils.words import amount_in_words_rupees
from django.contrib import messages as dj_messages
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed




def landing_page(request):
   return redirect("homepage")



def userview(request):
    token = request.COOKIES.get('jwt')
    if not token:
        return JsonResponse({'code':'TOKEN_MISSING'}, status=401)
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
        return JsonResponse({'ok': True, 'user_id': payload['user_id']})
    except ExpiredSignatureError:
        return JsonResponse({'code':'TOKEN_EXPIRED'}, status=401)
    except InvalidTokenError:
        return JsonResponse({'code':'TOKEN_INVALID'}, status=401)


# views.py (very top)
from hashids import Hashids

# Alphanumeric public code (good default)
_USER_HASH = Hashids(
    salt="CHANGE_ME_USERS_v1",   # put a secret from settings/env in prod
    min_length=12,               # length you like (12–16 looks good)
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
)

def _encode_user_pk(pk: int) -> str:
    return _USER_HASH.encode(pk)

# (Optional) if you ever need to decode back:
# def _decode_user_code(code: str) -> int | None:
#     try:
#         res = _USER_HASH.decode(code)
#         return res[0] if res else None
#     except Exception:
#         return None

#LOGIN AND SIGNUP PAGE CODE


class UserLoginAPIView(APIView):
    def get(self, request):
        return render(request, "userlogin.html")

    def post(self, request):
        email = (request.POST.get('email') or '').strip()
        password = request.POST.get('password') or ''
        user = authenticate(request, email=email, password=password)
        if user is None:
            return render(request, "userlogin.html",
                          {"message_type":"error","message":"Invalid email or password.","email": email},
                          status=401)

        if not user.is_active:
            return render(request, "userlogin.html",
                          {"message_type":"error","message":"Your account is inactive.","email": email},
                          status=403)

        payload = {
            'user_id': user.user_id,
            'exp': datetime.utcnow() + timedelta(minutes=settings.JWT_TTL_MINS),
            'iat': datetime.utcnow(),
        }
        token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)
        default_next = "/api/paginate/?page=1"
        next_url = (request.POST.get("next")
                    or request.GET.get("next")
                    or request.META.get("HTTP_REFERER")
                    or default_next)

        resp = redirect(next_url)
        resp.set_cookie("jwt", token, httponly=True, samesite="Lax")
        return resp


class UserDetailsView(APIView):
    permission_classes = []

    def get_user(self, token):
        if not token:
            raise AuthenticationFailed('Unauthenticated')
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
        except ExpiredSignatureError:
            raise AuthenticationFailed('Token expired')
        except InvalidTokenError:
            raise AuthenticationFailed('Invalid token')
        from application.models import User
        return User.objects.get(pk=payload['user_id'])

    def get(self, request):
        user = self.get_user(request.COOKIES.get('jwt'))
        data = UserSerializer(user).data
        # Don’t leak password hash (write_only anyway), just return the fields we care about
        return Response({
            'user_id': data['user_id'],
            'username': data['username'],
            'email': data['email'],
            'phone': data.get('phone'),
            'user_code': getattr(user, 'user_code', '')
        })

def forgot_password(request):
    User = get_user_model()
    ctx = {}
    if request.method == "POST":
        email = (request.POST.get("email") or "").strip().lower()
        new_password = request.POST.get("new_password") or ""
        confirm_password = request.POST.get("confirm_password") or ""

        if not email or not new_password or not confirm_password:
            ctx.update({"message_type": "error", "message": "All fields are required."})
            return render(request, "forgot_password.html", ctx)

        if new_password != confirm_password:
            ctx.update({"message_type": "error", "message": "Passwords do not match."})
            return render(request, "forgot_password.html", ctx)

        user = User.objects.filter(email__iexact=email).first()
        if not user:
            ctx.update({"message_type": "error", "message": "No account found for that email."})
            return render(request, "forgot_password.html", ctx)

        try:
            validate_password(new_password, user=user)
        except ValidationError as ve:
            ctx.update({"message_type": "error", "message": " ".join(ve.messages)})
            return render(request, "forgot_password.html", ctx)

        user.set_password(new_password)
        user.save()

        resp = render(request, "forgot_password.html", {
            "step": "done",
            "message_type": "success",
            "message": "Your password has been reset successfully. Please log in with your new password.",
        })
        resp.delete_cookie("jwt")
        return resp

    return render(request, "forgot_password.html", ctx)


# views.py  --- usersignup()
from datetime import datetime, timedelta
import jwt

def usersignup(request):
    if request.method == "GET":
        return render(request, "usersignup.html")

    elif request.method == "POST":
        role = request.POST.get('user_role')
        phone = request.POST.get('phone')  
        # create user
        user = User(
            username=request.POST['name'],
            email=request.POST['email'],
            age=request.POST['age'],
            gender=request.POST['gender'],
            user_role_id = 1 if role == 'buyer' else 2,
        )
        if (request.POST.get('password') and
            request.POST.get('confirm_password') and
            request.POST['password'] == request.POST['confirm_password']):
            user.set_password(request.POST['password'])
        # set phone for both cases
        user.phone = phone
        user.save()

        if not user.user_code:
            user.user_code = _encode_user_pk(user.pk)
            user.save(update_fields=['user_code'])

        # *** IMPORTANT: auto-login by issuing the JWT like your login view ***
        payload = {
            'user_id': user.user_id,
            'exp': datetime.utcnow() + timedelta(minutes=60),
            'iat': datetime.utcnow(),
        }
        token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)
        resp = redirect('addingaddress')   # or whatever name maps to address.html
        resp.set_cookie(key='jwt', value=token, httponly=True)
        return resp



class LogoutView(APIView):
    def post(self, request):
        # where should we go *after* the user logs in again?
        desired_next = (request.GET.get("next")
                        or request.POST.get("next")
                        or request.META.get("HTTP_REFERER")
                        or "/api/paginate/?page=1")

        login_url = f"{reverse('loginuser')}?next={desired_next}"
        resp = redirect(login_url)
        resp.delete_cookie('jwt')
        return resp

class AddressView(APIView):
    permission_classes = []  # we auth via JWT cookie

    def _user_id_from_jwt(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed('Unauthenticated')
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
        except ExpiredSignatureError:
            raise AuthenticationFailed('Token expired')
        except InvalidTokenError:
            raise AuthenticationFailed('Invalid token')
        return payload['user_id']

    def get(self, request):
        user_id = self._user_id_from_jwt(request)
        addresses = Address.objects.filter(user_id=user_id).order_by('-updated_at', '-created_at')
        data = AddressSerializer(addresses, many=True).data
        return Response({'addresses': data}, status=200)

    def post(self, request):
        user_id = self._user_id_from_jwt(request)
        ser = AddressSerializer(data=request.data)
        if ser.is_valid():
            ser.save(user_id=user_id)
            return Response(ser.data, status=201)
        return Response(ser.errors, status=400)

    def put(self, request):
        user_id = self._user_id_from_jwt(request)
        addr_id = request.query_params.get('address_id')
        if not addr_id:
            return Response({'detail':'address_id is required'}, status=400)
        try:
            addr = Address.objects.get(pk=addr_id)
        except Address.DoesNotExist:
            return Response({'detail':'Address not found'}, status=404)
        if addr.user_id != user_id:
            raise PermissionDenied('Not your address')

        ser = AddressSerializer(addr, data=request.data, partial=True)
        if ser.is_valid():
            ser.save()
            return Response(ser.data, status=200)
        return Response(ser.errors, status=400)

    def delete(self, request):
        user_id = self._user_id_from_jwt(request)
        addr_id = request.query_params.get('address_id')
        if not addr_id:
            return Response({'detail':'address_id is required'}, status=400)
        try:
            addr = Address.objects.get(pk=addr_id)
        except Address.DoesNotExist:
            return Response({'detail':'Address not found'}, status=404)
        if addr.user_id != user_id:
            raise PermissionDenied('Not your address')
        addr.delete()
        return Response(status=204)

class UpdatePanView(APIView):
    permission_classes = []  # Same pattern as AddressView (JWT cookie auth)

    def put(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({'detail': 'Unauthenticated'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
            user = User.objects.get(pk=payload['user_id'])
        except (ExpiredSignatureError, InvalidTokenError, User.DoesNotExist):
            return Response({'detail': 'Invalid or expired token'}, status=status.HTTP_401_UNAUTHORIZED)

        pan_card = request.data.get('pan_card')
        if not pan_card:
            return Response({'detail': 'PAN card required'}, status=status.HTTP_400_BAD_REQUEST)

        user.pan_card = pan_card
        user.save(update_fields=['pan_card'])
        return Response({'success': True, 'pan_card': user.pan_card}, status=status.HTTP_200_OK)
    

def _jwt_user_id(request):
    # same secret/alg as elsewhere
    token = request.COOKIES.get('jwt')
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
        return payload.get('user_id')
    except jwt.ExpiredSignatureError:
        return None


def _unique_cart_count_from_api(cookies):
    """
    Returns count of unique items in cart (ignores quantity and duplicate rows).
    Uniqueness is by product_id. If you have variants, include size/color in the key.
    """
    try:
        data = requests.get(f'{cart_url}/api/cartitems/', cookies=cookies).json()
        if not isinstance(data, list):
            return 0

        unique_keys = set()

        for it in data:
            # Try to get a stable product identifier from common shapes
            pid = (
                it.get('product_id')
                or (it.get('product', {}) or {}).get('id')
                or it.get('product')  # sometimes API returns just an id here
            )

            if pid is None:
                continue

            # If you have variants, uncomment the next two lines and use (pid, size, color)
            # size  = (it.get('size') or '').strip()
            # color = (it.get('color') or '').strip()
            # key = (str(pid), size, color)

            key = str(pid)  # unique by product only
            unique_keys.add(key)

        return len(unique_keys)
    except Exception:
        return 0


def _wishlist_count_from_api(cookies):
    """
    Returns the number of distinct wishlist items for the user.
    """
    try:
        data = requests.get(f'{cart_url}/api/wishlistitems/', cookies=cookies).json()
        if not isinstance(data, list):
            return 0
        unique_ids = set()
        for it in data:
            pid = (
                it.get('product_id')
                or (it.get('product', {}) or {}).get('id')
                or it.get('product')
            )
            if pid is not None:
                unique_ids.add(str(pid))
        return len(unique_ids)
    except Exception:
        return 0


def useraddress(request):
    user_id = _jwt_user_id(request)
    if not user_id:
        # gentle UX instead of crashing
        return render(request, 'address.html', {
            'message': "Your session expired. Please log in again before adding an address."
        })
    if request.method == "POST":
        Address.objects.create(
            user_id=user_id,
            door_no=request.POST['door_no'],
            street=request.POST['street'],
            area=request.POST['area'],
            city=request.POST['city'],
            state=request.POST['state'],
            pincode=request.POST['pincode'],
            country=request.POST['country'],
        )
        return redirect('/api/login/')  # or wherever you want next
    return render(request, 'address.html')



def order_address(request):
    user_id=requests.get(f'{user_url}/api/userview/',cookies=request.COOKIES).json()['user_id']

    if request.method=="POST":

        address_object=Address(user_id=user_id,
                                door_no= request.POST['door_no'],
                                street= request.POST['street'],
                                area=request.POST['area'],
                                city=request.POST['city'],
                                state= request.POST['state'],
                                pincode= request.POST['pincode'],
                                country= request.POST['country']
                            )
        
        address_object.save()
        return redirect('/api/checkout/')
    
    else:
        return render(request,'orderaddress.html')
        

# PRODUCTS CODE

def _session_expired(request) -> bool:
    # quick cookie check
    if 'jwt' not in request.COOKIES:
        return True
    # validate with userview (same contract cart uses)
    try:
        r = requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES, timeout=6)
        if r.status_code != 200:
            return True
        data = r.json() or {}
        return not (data.get('user_id') or data.get('id'))
    except Exception:
        return True


def products(request):
    response = requests.get(f'{product_url}/api/products/')
   # print(type(json.loads(response.content)))
    products=json.loads(response.content)
    return render(request, 'allproducts.html', {'products': products})

def product_info(request):
    response = requests.get(f'{product_url}/api/allproducts/')
    products=json.loads(response.content)
    return render(request, 'products.html',{ "products" :products})


# HOMEPAGE CODE
# View function for the homepage
def homepage(request, page = None,searchproduct=None):
    # Get the page number from the GET parameters, default to 1 if not provided
    page_number = request.GET.get('page',1)

    if 'searchproduct' in request.GET.keys():
        searchproduct = request.GET['searchproduct']

    # Build the API URL based on whether a search term is provided
    if searchproduct:
        url = f'{product_url}/api/homepage/?searchproduct={searchproduct}&page={page_number}'

    else:
        url = f'{product_url}/api/setproducts/?page={page_number}'
    query_params = {'page' : page_number}
    response = requests.get(url)
    data = response.json()
    products = data['results']

    for product in products:
        product['image']=product['image'].replace('http://152.14.0.14','http://127.0.0.1')

    next_url = data['next']
    prev_url = data['previous']
    page = data['page']
# Unique cart count for navbar badge
    cart_count = _unique_cart_count_from_api(request.COOKIES)
    wishlist_count = _wishlist_count_from_api(request.COOKIES)


    context = {
        'products': products,
        'next_url': next_url,
        'next_page': int(page)+1,
        'prev_url': prev_url,
        'prev_page': int(page)-1,
        'cart_count': cart_count,
        'wishlist_count': wishlist_count,
        'session_expired': 1 if _session_expired(request) else 0,
        'read_only': 1 if _session_expired(request) else 0,
    }
    return render(request, 'allproducts.html', context)



# View function for paginating products
@ensure_csrf_cookie
def paginate(request, page=None, search=None):
    if 'jwt' in request.COOKIES.keys():
        # Get user_id from the authenticated user's information
        user = requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES).json()
    else:
        return redirect(f'{user_url}/api/login/')

    page_number = request.GET.get('page', 1)  # Default to page 1 if no page number is specified

    if 'search' in request.GET.keys():
        search = request.GET['search']

    if search:
        url = f'{product_url}/api/productsearch/?search={search}&page={page_number}'
    else:
        url = f'{product_url}/api/getproducts/?page={page_number}'

    query_params = {'page': page_number}
    response = requests.get(url)
    data = response.json()

    products = data['results']
    for product in products:
        product['image'] = product['image'].replace('http://152.14.0.14', 'http://127.0.0.1')

    next_url = data['next']
    prev_url = data['previous']
    page = data['page']

    # Get cart count (unique products only)
    cart_count = _unique_cart_count_from_api(request.COOKIES)
    wishlist_count = _wishlist_count_from_api(request.COOKIES)
    context = {
        'products': products,
        'next_url': next_url,
        'next_page': int(page) + 1,
        'prev_url': prev_url,
        'prev_page': int(page) - 1,
        'user': user,
        'cart_count': cart_count, 
        'wishlist_count': wishlist_count, 
        'session_expired': 1 if _session_expired(request) else 0,
        'read_only': 1 if _session_expired(request) else 0, 
    }
    return render(request, 'products.html', context)



class GetUserIdAPIView(views.APIView): #Get the UserId
    def get(self, request, *args, **kwargs):
        user_id = kwargs['user_id']
        user = User.objects.get(user_id=user_id)
        return Response( UserSerializer(user).data)



def profile(request):
    # Require auth like your other pages
    if 'jwt' not in request.COOKIES:
        return redirect(f'{user_url}/api/login/')

    # user details
    try:
        user_data = requests.get(
            f'{user_url}/api/userview/', cookies=request.COOKIES, timeout=6
        ).json()
    except Exception:
        user_data = {}

    # addresses list
    try:
        addr_resp = requests.get(
            f'{user_url}/api/getaddress/', cookies=request.COOKIES, timeout=6
        )
        addresses = (addr_resp.json() or {}).get('addresses', [])
    except Exception:
        addresses = []

    ctx = {
        'user_name':  user_data.get('username') or 'Customer',
        'user_email': user_data.get('email') or '',
        'user_phone': user_data.get('phone') or '',
        'user_pan':   user_data.get('pan_card') or '',
        'addresses':  addresses,  # we’ll also dump this as JSON for JS
    }
    return render(request, 'profile.html', ctx)


# CART & WISHLIST SERVICE CODE

SNAPSHOT_CART_KEY      = "__cart_snapshot__"
SNAPSHOT_WISHLIST_KEY  = "__wishlist_snapshot__"
SNAPSHOT_TOTAL_KEY     = "__cart_total_snapshot__"

def _no_store(response):
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response["Pragma"] = "no-cache"
    response["Expires"] = "0"
    return response

def _simulate_cart_eta(seed=None):
    now = int(datetime.now(tz=timezone.utc).timestamp())
    if seed is None:
        seed = now
    r = random.Random(hash(seed) & 0xffffffff)
    add_days  = r.randint(2, 6)
    add_hours = r.randint(0, 12)
    return now + add_days*86400 + add_hours*3600


@never_cache
def cart(request):
    cartitems, wishlistitems, cart_total = [], [], 0.0
    session_expired = False

    # 1) quick cookie check
    if 'jwt' not in request.COOKIES:
        session_expired = True

    # 2) try to fetch live data if session seems valid
    if not session_expired:
        try:
            u = requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES, timeout=8).json()
            user_id = u.get('user_id') or u.get('id')
            if not user_id:
                session_expired = True
        except Exception:
            session_expired = True

    if not session_expired:
        # ----- LIVE FETCH (and snapshot it) -----
        try:
            cart_rows = requests.get(f'{cart_url}/api/cartitems/', cookies=request.COOKIES, timeout=8).json()
            if not isinstance(cart_rows, list):
                cart_rows = []
        except Exception:
            cart_rows = []

        total = 0.0
        out = []
        for idx, row in enumerate(cart_rows):
            pid = row.get('product_id')
            qty = int(row.get('quantity', 1) or 1)

            try:
                p = requests.get(
                    f'{product_url}/api/productview/{pid}/',
                    cookies=request.COOKIES, timeout=8
                ).json()
            except Exception:
                p = {}

            if 'image' in p:
                p['image'] = p['image'].replace('http://152.14.0.14', 'http://127.0.0.1')

            price = float(p.get('price', 0) or 0)
            row['product'] = p
            row['total_price'] = round(qty * price, 2)

            # --- NEW: ETA per item (seeded so it’s stable per product) ---
            seed = f"{pid}:{qty}:{idx}"
            eta_ts = _simulate_cart_eta(seed)
            eta_date = datetime.fromtimestamp(eta_ts, tz=timezone.utc).strftime("%b %d")
            row['eta_display'] = f"Delivery by {eta_date}"
            row['eta_ts'] = eta_ts  # if you ever want to sort/group

            out.append(row)
            total += qty * price

        cartitems  = out
        cart_total = round(total, 2)


        # wishlist
        try:
            wraw = requests.get(f'{cart_url}/api/wishlistitems/', cookies=request.COOKIES, timeout=8).json()
            wishlistitems = wraw if isinstance(wraw, list) else []
            # normalize wishlist rows (add product blobs for template parity)
            for w in wishlistitems:
                pid = w.get('product_id')
                try:
                    p = requests.get(f'{product_url}/api/productview/{pid}/', cookies=request.COOKIES, timeout=8).json()
                except Exception:
                    p = {}
                if 'image' in p:
                    p['image'] = p['image'].replace('http://152.14.0.14', 'http://127.0.0.1')
                w['product'] = p
                w['quantity'] = int(w.get('quantity', 1) or 1)
        except Exception:
            wishlistitems = []

        # snapshot for later read-only rendering
        request.session[SNAPSHOT_CART_KEY]     = cartitems
        request.session[SNAPSHOT_WISHLIST_KEY] = wishlistitems
        request.session[SNAPSHOT_TOTAL_KEY]    = float(cart_total)
        request.session.modified = True

    else:
        cartitems     = request.session.get(SNAPSHOT_CART_KEY, []) or []
        wishlistitems = request.session.get(SNAPSHOT_WISHLIST_KEY, []) or []
        cart_total    = request.session.get(SNAPSHOT_TOTAL_KEY, 0.0) or 0.0

    # Ensure ETA exists for each item in snapshot too
    for idx, row in enumerate(cartitems):
        if not row.get('eta_display'):
            pid = row.get('product_id')
            seed = f"snap:{pid}:{idx}"
            eta_ts = _simulate_cart_eta(seed)
            eta_date = datetime.fromtimestamp(eta_ts, tz=timezone.utc).strftime("%b %d")
            row['eta_display'] = f"Delivery by {eta_date}"
            row['eta_ts'] = eta_ts

    resp = render(request, "cart.html", {
        "cartitems": cartitems,
        "wishlistitems": wishlistitems,
        "cart_total": cart_total,
        "session_expired": 1 if session_expired else 0,
        "read_only": 1 if session_expired else 0, 
        "cart_count": len({item.get('product_id') for item in cartitems if item.get('product_id')}),
        "wishlist_count": len({item.get('product_id') for item in wishlistitems if item.get('product_id')}),
     })
    return _no_store(resp)
    


@require_POST
def add_to_cart_ajax(request):
    if 'jwt' not in request.COOKIES:
        return JsonResponse({'ok': False, 'auth': False, 'error': 'Not authenticated'}, status=401)

    product_id = request.POST.get('product_id')
    if not product_id:
        return JsonResponse({'ok': False, 'error': 'missing product_id'}, status=400)

    try:
        # forward to your cart microservice (no redirect)
        r = requests.post(f'{cart_url}/api/addtocart/', data={'product_id': product_id}, cookies=request.COOKIES)
        if r.status_code >= 400:
            return JsonResponse({'ok': False, 'error': 'cart service error', 'status': r.status_code, 'body': r.text}, status=502)
    except Exception as e:
        return JsonResponse({'ok': False, 'error': 'cart service unreachable'}, status=502)

    cart_count = 0
    try:
        cart_resp = requests.get(f'{cart_url}/api/cartitems/', cookies=request.COOKIES).json()
        if isinstance(cart_resp, list):
            cart_count = len({item.get('product_id') for item in cart_resp if item.get('product_id')})
    except Exception:
        pass

    return JsonResponse({'ok': True, 'cart_count': cart_count})





def add_quantity(request):

    if 'jwt' in request.COOKIES.keys():
        # Get user_id from the authenticated user's information
        user_id = requests.get(f'{user_url}/api/userview/', cookies = request.COOKIES).json()['user_id']
    else:
        return redirect(f'{user_url}/api/login/')
    
    product_id =  request.GET['product_id']

    # Make a request to the addtocart API with the request data and cookies
    reposne = requests.post(f'{cart_url}/api/addtocart/',data=request.GET, cookies=request.COOKIES).json()

    return redirect('/api/cart/')

def reduce_quantity(request):
    if 'jwt' in request.COOKIES.keys():

        response = requests.get(f'{user_url}/api/userview/', cookies = request.COOKIES).json()['user_id']
    else:

        return redirect(f'{user_url}/api/login/')
    
    product_id =  request.GET['product_id']
    reposne = requests.post(f'{cart_url}/api/reducequantity/',data=request.GET, cookies=request.COOKIES).json()
    return redirect('/api/cart/')

def delete_product(request):
    if 'jwt' in request.COOKIES.keys():

        resposne = requests.get(f'{user_url}/api/userview/', cookies = request.COOKIES).json()['user_id']
    else:

        return redirect(f'{user_url}/api/login/')
    
    product_id =  request.GET['product_id']
    reposne = requests.post(f'{cart_url}/api/deleteproduct/',data=request.GET, cookies=request.COOKIES).json()
    return redirect('/api/cart/')

@require_POST
def clear_cart(request):
    # require login like you already do
    if 'jwt' not in request.COOKIES: 
        return redirect(f'{user_url}/api/login/')
    try:
        # IMPORTANT: no product_id, and POST (not GET)
        r = requests.post(f'{cart_url}/api/clearcart/', cookies=request.COOKIES, timeout=6)
        data = r.json() if r.ok else {'message': 'Could not clear cart'}
    except requests.RequestException:
        data = {'message': 'Could not clear cart'}
    # optional UX message
    messages.success(request, data.get('message', 'Cart cleared'))
    return redirect('/api/cart/')


def get_user_address(request):
    user_id=requests.get(f'{user_url}/api/userview/',cookies=request.COOKIES).json()['user_id']
    # Get the user's address from the Address model
    address=Address.objects.filter(user_id=user_id).first()
    context={'address':address}
    return render(request, 'address.html', context)

@require_POST
def move_cart_to_wishlist(request):
    if 'jwt' not in request.COOKIES: return redirect(f'{user_url}/api/login/')
    product_id = request.POST.get('product_id')
    requests.post(f'{cart_url}/api/move-cart-to-wishlist/', data={'product_id': product_id}, cookies=request.COOKIES, timeout=8)
    return redirect('/api/cart/?open=wishlist')



@require_POST
def add_to_wishlist_ajax(request):
    if 'jwt' not in request.COOKIES:
        return JsonResponse({'ok': False, 'auth': False}, status=401)

    pid = request.POST.get('product_id')
    if not pid:
        return JsonResponse({'ok': False, 'error': 'missing product_id'}, status=400)

    try:
        # correct cart service endpoint
        r = requests.post(
            f'{cart_url}/api/addtowishlist/',
            data={'product_id': pid},
            cookies=request.COOKIES,
            timeout=8
        )
        if r.status_code >= 400:
            return JsonResponse(
                {'ok': False, 'error': 'wishlist endpoint error', 'status': r.status_code, 'body': r.text},
                status=502
            )
    except Exception:
        return JsonResponse({'ok': False, 'error': 'wishlist endpoint unreachable'}, status=502)

    # optional: return fresh wishlist count
    wl_count = 0
    try:
        w = requests.get(f'{cart_url}/api/wishlistitems/', cookies=request.COOKIES, timeout=8).json()
        if isinstance(w, list):
            wl_count = len({ int(i.get('product_id')) for i in w if i.get('product_id') })
    except Exception:
        pass

    return JsonResponse({'ok': True, 'wishlist_count': wl_count})




def remove_wishlist_item(request):
    if 'jwt' not in request.COOKIES:
        return redirect(f'{user_url}/api/login/')
    product_id = request.GET.get('product_id')
    requests.post(f'{cart_url}/api/removewishlist/', data={'product_id': product_id}, cookies=request.COOKIES)
    return redirect('/api/cart/?open=wishlist')

@require_POST
def move_wishlist_to_cart(request):
    if 'jwt' not in request.COOKIES:
        return redirect(f'{user_url}/api/login/')

    product_id = request.POST.get('product_id')
    if not product_id:
        messages.error(request, "Missing product id")
        return redirect('/api/cart/?open=wishlist')

    r = requests.post(
        f'{cart_url}/api/move-wishlist-to-cart/',
        data={'product_id': product_id},
        cookies=request.COOKIES,
        timeout=8
    )
    if r.status_code >= 400:
        messages.error(request, f"Move failed ({r.status_code})")
    else:
        messages.success(request, "Moved to cart")

    return redirect('/api/cart/?open=wishlist')

@require_GET
def wishlist_addquantity(request):
    if 'jwt' not in request.COOKIES:
        return redirect(f'{user_url}/api/login/')
    pid = request.GET.get('product_id')
    if pid:
        requests.post(f'{cart_url}/api/wishlist/addquantity/', data={'product_id': pid}, cookies=request.COOKIES, timeout=8)
    return redirect('/api/cart/?open=wishlist')

@require_GET
def wishlist_reducequantity(request):
    if 'jwt' not in request.COOKIES:
        return redirect(f'{user_url}/api/login/')
    pid = request.GET.get('product_id')
    if pid:
        requests.post(f'{cart_url}/api/wishlist/reducequantity/', data={'product_id': pid}, cookies=request.COOKIES, timeout=8)
    return redirect('/api/cart/?open=wishlist')



# CHECKOUT SERVICE CODE 
# ---------- checkout sandbox helpers ----------

USE_CHECKOUT_SANDBOX = True           # keep cart untouched while on checkout
SESSION_KEY   = "__checkout_items__"  # {product_id(str): qty(int)}
SESSION_CACHE = "__checkout_cache__"

def _no_store(response):
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response["Pragma"] = "no-cache"
    response["Expires"] = "0"
    return response


def _fetch_product_for_checkout(request, pid: str) -> dict:
    try:
        product = requests.get(
            f'{product_url}/api/productview/{pid}/',
            cookies=request.COOKIES, timeout=8
        ).json()
    except Exception:
        product = {}
    if 'image' in product:
        product['image'] = product['image'].replace('http://152.14.0.14', 'http://127.0.0.1')
    return product


def _seed_checkout_snapshot_from_cart(request, *, force: bool = False) -> None:
    """
    Seed/refresh the session snapshot from the REAL cart.

    IMPORTANT change:
    - We DO NOT reseed if a snapshot dict already exists in session
      (even if it's empty). This lets the user clear the last product
      without the list magically coming back on refresh.
    """
    snap_in_session = request.session.get(SESSION_KEY)

    if not force:
        # If a snapshot is already present (even empty), keep it.
        if isinstance(snap_in_session, dict):
            return

    # Fetch current cart rows (be robust to {"message": "..."} empty payloads)
    try:
        raw = requests.get(
            f'{cart_url}/api/cartitems/', cookies=request.COOKIES, timeout=8
        ).json()
        if isinstance(raw, list):
            cart_rows = raw
        else:
            # service can return {"message": "cart empty"}; treat as empty list
            cart_rows = []
    except Exception:
        cart_rows = []

    snap: dict[str, int] = {}
    for row in cart_rows:
        pid = str(row.get('product_id') or '')
        qty = int(row.get('quantity', 1) or 1)
        if pid:
            snap[pid] = snap.get(pid, 0) + max(1, qty)

    request.session[SESSION_KEY] = snap
    # refresh cache only when reseeding
    request.session[SESSION_CACHE] = {}
    request.session.modified = True


def _normalize_snapshot_for_template(request):
    snap  = request.session.get(SESSION_KEY, {}) or {}
    cache = request.session.get(SESSION_CACHE, {}) or {}

    items, total = [], 0.0
    for pid, qty in snap.items():
        p = cache.get(pid)
        if not p:
            p = _fetch_product_for_checkout(request, pid)
            cache[pid] = p

        price = float(p.get('price', 0) or 0)
        items.append({
            "product_id": pid,
            "quantity": qty,
            "price": price,
            "product_name": p.get("product_name"),
            "image": p.get("image") or "",
            "product": p,
            "total_price": qty * price,
        })
        total += qty * price

    request.session[SESSION_CACHE] = cache
    request.session.modified = True
    return items, round(total, 2)
# ---------- end helpers ----------

from decimal import Decimal
PLATFORM_FEE_RS = Decimal("5.00")

from django.views.decorators.cache import never_cache

PLATFORM_FEE_RS = 5.0  # keep as float

@never_cache
def checkout(request):
    if request.method != 'GET':
        return start_payment_from_checkout(request)

    if 'jwt' not in request.COOKIES:
        return redirect(f'{user_url}/api/login/')

    # ---- defaults so they always exist ----
    cart_items: list = []
    cart_total: float = 0.0

    # user
    user = requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES, timeout=8).json()
    user_name  = user.get('username', 'Customer')
    user_phone = user.get('phone') or '+91 xxxxxxxxxx'
    user_email = user.get('email')

    # addresses
    try:
        address_response = requests.get(f'{user_url}/api/getaddress/', cookies=request.COOKIES, timeout=8).json()
        addresses = address_response.get('addresses', []) or []
    except Exception:
        addresses = []

    # allow seed clear
    if request.GET.get('seed'):
        request.session.pop(SESSION_KEY, None)
        request.session.pop(SESSION_CACHE, None)

    # ---- snapshot vs live ----
    if USE_CHECKOUT_SANDBOX:
        _seed_checkout_snapshot_from_cart(request, force=(request.GET.get('seed') == '1'))
        cart_items, cart_total = _normalize_snapshot_for_template(request)
    else:
        try:
            cart_items_response = requests.get(
                f'{cart_url}/api/cartitems/', cookies=request.COOKIES, timeout=8
            ).json()
            if not isinstance(cart_items_response, list):
                cart_items_response = []
        except Exception:
            cart_items_response = []

        cart_total = 0.0
        for item in cart_items_response:
            pid = item.get("product_id")
            try:
                product = requests.get(
                    f'{product_url}/api/productview/{pid}/',
                    cookies=request.COOKIES, timeout=8
                ).json()
            except Exception:
                product = {}
            if 'image' in product:
                product['image'] = product['image'].replace('http://152.14.0.14', 'http://127.0.0.1')
            item['product'] = product
            price = float(product.get('price', 0) or 0)
            item['total_price'] = int(item.get('quantity', 1)) * price
            cart_total += item['total_price']
        cart_items = cart_items_response

    # ---- compute fees in BOTH cases (outside the branch) ----
    shipping_fee  = 0.0 if cart_total == 0 else (0.0 if cart_total >= 1500 else 100.0)
    platform_fee  = 0.0 if cart_total == 0 else PLATFORM_FEE_RS
    total_payable = cart_total + shipping_fee + platform_fee

    # ---- freeze snapshot for payment page ----
    request.session['checkout_snapshot'] = {
        "items": cart_items,
        "item_count": len(cart_items),
        "cart_total": float(cart_total),
        "shipping_fee": float(shipping_fee),
        "platform_fee": float(platform_fee),
        "total_payable": float(total_payable),
        "final_total": float(total_payable),
    }
    request.session.modified = True

    # ---- render ----
    resp = render(request, "checkout.html", {
        'orders_data': cart_items,
        'addresses': addresses,
        'cart_total': cart_total,
        'shipping_fee': shipping_fee,
        'platform_fee': platform_fee,
        'total_payable': total_payable,
        'user_name': user_name,
        'user_phone': user_phone,
        'user_email': user_email,
    })
    resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp["Pragma"] = "no-cache"
    resp["Expires"] = "0"
    return _no_store(resp)
    


def _redirect_back_to_summary():
    return redirect(reverse('checkout'))

@require_POST
@never_cache
def add_quantity_checkout(request):
    if 'jwt' not in request.COOKIES:
        return _no_store(redirect(f'{user_url}/api/login/'))

    pid = str(request.POST.get('product_id') or '')
    if USE_CHECKOUT_SANDBOX and pid:
        _seed_checkout_snapshot_from_cart(request)  # safe: won’t reseed if dict exists
        snap = request.session.get(SESSION_KEY, {}) or {}
        snap[pid] = int(snap.get(pid, 0)) + 1
        request.session[SESSION_KEY] = snap
        request.session.modified = True
    elif pid:
        requests.post(
            f'{cart_url}/api/addtocart/',
            data={'product_id': pid},
            cookies=request.COOKIES, timeout=8
        )

    return _no_store(_redirect_back_to_summary())

@require_POST
@never_cache
def reduce_quantity_checkout(request):
    if 'jwt' not in request.COOKIES:
        return _no_store(redirect(f'{user_url}/api/login/'))

    pid = str(request.POST.get('product_id') or '')
    if USE_CHECKOUT_SANDBOX and pid:
        _seed_checkout_snapshot_from_cart(request)
        snap = request.session.get(SESSION_KEY, {}) or {}
        if pid in snap and int(snap[pid]) > 1:
            snap[pid] = int(snap[pid]) - 1
            request.session[SESSION_KEY] = snap
            request.session.modified = True
        # if already 1, leave as 1 (your UI disables minus at 1)
    elif pid:
        requests.post(
            f'{cart_url}/api/reducequantity/',
            data={'product_id': pid},
            cookies=request.COOKIES, timeout=8
        )

    return _no_store(_redirect_back_to_summary())

@require_POST
@never_cache
def delete_product_checkout(request):
    if 'jwt' not in request.COOKIES:
        return _no_store(redirect(f'{user_url}/api/login/'))

    pid = str(request.POST.get('product_id') or '')
    if USE_CHECKOUT_SANDBOX and pid:
        _seed_checkout_snapshot_from_cart(request)
        snap = request.session.get(SESSION_KEY, {}) or {}
        if pid in snap:
            snap.pop(pid, None)
            request.session[SESSION_KEY] = snap
            request.session.modified = True
        # also clear any cached product json for neatness
        cache = request.session.get(SESSION_CACHE, {}) or {}
        if pid in cache:
            cache.pop(pid, None)
            request.session[SESSION_CACHE] = cache
    elif pid:
        requests.post(
            f'{cart_url}/api/deleteproduct/',
            data={'product_id': pid},
            cookies=request.COOKIES, timeout=8
        )
    return _no_store(_redirect_back_to_summary())




#PAYMENT PAGE CODE

import time 

def mark_session_expired(request):
    """
    Mark that the user session/token has expired so the frontend
    can show the session-expired modal on next page load.
    """
    request.session["__session_expired__"] = True
    request.session.modified = True


def _get_current_user_id(request):
    try:
        data = requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES, timeout=8).json()
        return data.get('user_id')
    except Exception:
        return None


def _clear_messages(request):
    from django.contrib.messages import get_messages
    for _ in get_messages(request):
        pass

def _norm_method(m: dict) -> dict:
    tp = m.get("method_type") or m.get("type")

    brand = (m.get("card_brand") or "CARD").upper()
    last4 = (m.get("last4") or "")

    # raw UPI value if backend sends it
    upi_vpa = m.get("upi_vpa") or m.get("vpa") or m.get("upi_id") or ""

    # base masked text coming from backend
    raw_masked = m.get("masked_display") or (
        f"{brand} •••• {last4}" if tp == "card" else (upi_vpa or "UPI ••••")
    )

    # 🔹 strip any "Default"/"DEFAULT" that backend might have added
    if raw_masked:
        raw_masked = raw_masked.replace("Default", "").replace("DEFAULT", "").strip()

    masked = raw_masked

    # 🔹 special masking for UPI: 77803847483@paytm -> 778.....83@paytm
    if tp == "upi" and upi_vpa and "@" in upi_vpa:
        try:
            name, domain = upi_vpa.split("@", 1)
            if len(name) > 5:
                masked = f"{name[:3]}.....{name[-2:]}@{domain}"
            else:
                masked = upi_vpa
        except ValueError:
            pass  # fall back to whatever masked already is

    return {
        "id": m.get("id") or m.get("_id") or m.get("pk"),
        "method_type": tp,
        "masked_display": masked,
        "card_brand": brand,
        "last4": last4,
        "exp_month": m.get("exp_month"),
        "exp_year": m.get("exp_year"),
        "card_holder_name": m.get("card_holder_name"),
        "is_default": bool(m.get("is_default") or m.get("default") or m.get("isDefault")),
        "upi_provider_name": m.get("upi_provider_name") or m.get("provider_name"),
        "upi_vpa": upi_vpa,
    }


def _back_to_pay(request):
    # keep this for any non-AJAX usage
    return reverse("pay_start")
@require_POST
def saved_method_default(request, mid: int):
    # use the same helper you already use elsewhere
    user_id = _get_current_user_id(request)
    method_type = request.GET.get("type")  # 'upi' or 'card'

    ok = False

    try:
        if not user_id or not method_type:
            print("DEFAULT LOCAL ERR: missing user_id or type ->",
                  "user_id:", user_id, "type:", method_type)
        else:
            # send user_id & type as QUERY PARAMS, not JSON
            resp = requests.patch(
                f"{payment_url.rstrip('/')}/payment-methods/{mid}/default/",
                params={"user_id": user_id, "type": method_type},
                cookies=request.COOKIES,
                timeout=6,
            )
            ok = resp.ok
            if not ok:
                print("DEFAULT FAIL:", resp.status_code, resp.text[:300])
    except Exception as e:
        print("DEFAULT ERR:", e)

    # AJAX case
    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        return JsonResponse({"ok": ok}, status=200 if ok else 400)

    # non-AJAX fallback
    return redirect(_back_to_pay(request))


@require_POST
def saved_method_delete(request, mid: int):
    ok = False
    try:
        resp = requests.delete(
            f"{payment_url.rstrip('/')}/payment-methods/{mid}/",
            cookies=request.COOKIES,
            headers={"X-CSRFToken": request.COOKIES.get("csrftoken", "")},
            timeout=6,
        )
        ok = resp.ok
        if not ok:
            print("DELETE FAIL:", resp.status_code, resp.text[:300])
    except Exception as e:
        print("DELETE ERR:", e)

    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        return JsonResponse({"ok": ok}, status=200 if ok else 400)

    return redirect(_back_to_pay(request))


from django.views.decorators.cache import never_cache
from django.shortcuts import render, redirect

@never_cache
def pay_start(request):


    # 1) Check if session is expired using your helper
    session_expired = _session_expired(request)   # you already have this function above

    # 2) Get cart snapshot from session (set earlier by cart/checkout views)
    cartitems     = request.session.get(SNAPSHOT_CART_KEY, []) or []
    wishlistitems = request.session.get(SNAPSHOT_WISHLIST_KEY, []) or []
    cart_total    = float(request.session.get(SNAPSHOT_TOTAL_KEY, 0.0) or 0.0)

    # 3) Load addresses ONLY if session looks valid
    addresses = []
    if not session_expired:
        try:
            r = requests.get(f'{user_url}/api/getaddress/', cookies=request.COOKIES, timeout=6)
            if r.status_code == 200:
                data = r.json() or {}
                addresses = data.get('addresses') or []
            else:
                # 401 / 403 / anything else → treat as expired, but STAY on this page
                session_expired = True
        except Exception:
            # network error etc → treat as expired
            session_expired = True

    # 4) If user is logged in (session not expired) BUT has no addresses → go to HTML address page
    if not session_expired and not addresses:
        # ⚠️ NOTE: name='addingaddress' → /api/address/ (HTML form)
        return redirect('addingaddress')

    # 5) Prepare context for payments.html
    ctx = {
        "cartitems": cartitems,
        "cart_total": cart_total,
        "addresses": addresses,
        "cart_count": len({item.get('product_id') for item in cartitems if item.get('product_id')}),
        "wishlist_count": len({item.get('product_id') for item in wishlistitems if item.get('product_id')}),
        "session_expired": 1 if session_expired else 0,
        "read_only": 1 if session_expired else 0,
    }

    resp = render(request, "payments.html", ctx)
    return _no_store(resp)   # you already use this in cart()


@ensure_csrf_cookie
@require_POST
def start_payment_from_checkout(request):
    """
    Opens the payment page using the exact values frozen by checkout().
    Also stashes a minimal order snapshot in the session as __pending_order__
    so we can create a 'Payment Failed' order if the user bails or times out.
    """
    # must be logged in
    if 'jwt' not in request.COOKIES:
        return redirect(f'{user_url}/api/login/')

    # 1) Which address?
        # 1) Which address? — be tolerant to different field names and JSON bodies
    # Try POST form first, then JSON body if present
    raw_sel = (
        request.POST.get('address_id') or
        request.POST.get('selected_address_id') or
        request.POST.get('selectedAddressId') or
        request.POST.get('address')  # sometimes radios are named "address"
    )
    if not raw_sel and request.META.get("CONTENT_TYPE", "").startswith("application/json"):
        try:
            body = json.loads(request.body.decode("utf-8") or "{}")
            raw_sel = (
                body.get("address_id") or body.get("selected_address_id") or
                body.get("selectedAddressId") or body.get("address")
            )
        except Exception:
            raw_sel = None

    try:
        sel_addr_id = int(raw_sel) if raw_sel is not None else None
    except Exception:
        sel_addr_id = None

    # Load user address book
    try:
        addr_res = requests.get(
            f'{user_url}/api/getaddress/',
            cookies=request.COOKIES,
            timeout=8
        )
        status_code = addr_res.status_code
        addr_json = addr_res.json() if addr_res.content else {}
    except Exception:
        status_code = None
        addr_json = {}

    addresses = addr_json.get('addresses', []) or []

    # 2) If token expired / unauthorised, go back to checkout
    #    (checkout + payment templates now both have the session modal JS)
        # 2) If token expired / unauthorised, go back to checkout and show session modal
    if status_code in (401, 403):
        request.session.pop('checkout_snapshot', None)
        mark_session_expired(request)  
        return redirect(reverse("checkout"))


    # 3) Real "no addresses" case
    if not addresses:
        messages.error(request, "No address on file. Please add an address.")
        return redirect('/api/getaddress/')


    # Pick the selected one, or default to the first — but only if nothing valid was sent
    def _aid(a: dict) -> str:
        for k in ('address_id', 'id', 'addressId', 'aid'):
            v = a.get(k)
            if v is not None:
                return str(v)
        return ''

    if sel_addr_id is not None:
        address = next((a for a in addresses if _aid(a) == str(sel_addr_id)), None)
        if not address:
            # if the id didn’t match any, fall back to the first but log it
            print("[checkout] WARN: selected id", sel_addr_id, "not found, using first")
            address = addresses[0]
    else:
        address = addresses[0]

    print("[checkout] using address_id =", _aid(address))


    # 2) Pull the frozen checkout snapshot (set in your checkout view)
    snap = request.session.get('checkout_snapshot')
    if not snap:
        mark_session_expired(request)  
        # optional: keep messages if you want
        messages.error(request, "Session expired. Please open checkout again.")
        return redirect(reverse("checkout"))


    # 3) Normalize numbers (JSON-safe floats/ints only)
    items         = snap.get("items", [])
    item_count    = int(snap.get("item_count", 0))
    cart_total    = float(snap.get("cart_total", 0.0))
    shipping_fee  = float(snap.get("shipping_fee", 0.0))
    platform_fee  = float(snap.get("platform_fee", 0.0))
    total_payable = float(snap.get("total_payable", 0.0))

    user_id = _get_current_user_id(request)

    # 4) Build the order snapshot we’ll keep during payment
    def _fmt_address(a: dict) -> str:
        parts = [a.get('doorno'), a.get('street'), a.get('landmark'),
             a.get('city'), a.get('state'), a.get('pincode')]
        return ', '.join(str(p) for p in parts if p)

    recipient_name  = (address.get('customer_name')
                    or f"{address.get('firstname','')} {address.get('lastname','')}".strip())
    recipient_phone = address.get('customer_phone') or address.get('phone') or ''
    address_label   = address.get('address_type') or 'Home'
    shipping_addr   = _fmt_address(address)

    # 4) Build the order snapshot we’ll keep during payment
    orders_data = {
        "user_id": user_id,
        "address_id": address.get("address_id"),
        "address": address,        # handy for the payment page UI

        # --- NEW: freeze address fields into the order snapshot ---
        "recipient_name":  recipient_name,
        "recipient_phone": recipient_phone,
        "address_label":   address_label,
        "shipping_address": shipping_addr,

        "items": items,
        "summary": {
            "item_count": item_count,
            "cart_total": cart_total,
            "shipping_fee": shipping_fee,
            "platform_fee": platform_fee,
            "final_total": total_payable,
            "total_payable": total_payable,
        }
    }
    
    # >>> KEY LINES: keep a copy for timeout/failure <<<
    request.session['__pending_order__']   = orders_data
    request.session.modified = True
    # <<< KEY LINES

    # 5) (Optional) create a payment intent with your gateway
    # If you don’t have a gateway service, you can skip this whole try/except
    payment_payload = {}
    try:
        intent_url = f"{payment_url.rstrip('/')}/payments/intents/"
        idemp      = str(uuid.uuid4())
        payload = {
            "order_id": 0,
            "user_id": user_id,
            "amount": round(total_payable, 2),
            "currency": "INR",
            "provider": "razorpay",
            "idempotency_key": idemp,
            "metadata": {"source": "cart_checkout"}
        }
        r = requests.post(intent_url, json=payload, timeout=10)
        if r.ok:
            payment_payload = r.json()
            request.session['__pending_payment__'] = payment_payload
            request.session.modified = True
        # if it fails, we still show payment page; your JS can switch to UPI/COD UI
    except Exception:
        pass

     # 5.1) Load saved payment methods for this user (cards & UPI)
    saved_methods = []
    try:
        if user_id:
            rsm = requests.get(
                f"{payment_url.rstrip('/')}/payment-methods/",
                params={"user_id": user_id},
                cookies=request.COOKIES,
                timeout=6
            )
            print("FETCH SAVED ->", user_id, rsm.status_code, rsm.text[:500])
            if rsm.ok:
                raw = rsm.json() or []
                if isinstance(raw, dict) and "results" in raw:
                    raw = raw["results"]
                saved_methods = [_norm_method(x) for x in raw if x]
    except Exception as e:
        print("FETCH SAVED ERR:", e)
        saved_methods = []
            # Split for template (Django template can't do selectattr like Jinja)
        # Split + sort so default always comes first
    saved_upis = sorted(
        [m for m in saved_methods if m.get("method_type") == "upi"],
        key=lambda m: (0 if m.get("is_default") else 1, m.get("id") or 0),
    )
    saved_cards = sorted(
        [m for m in saved_methods if m.get("method_type") == "card"],
        key=lambda m: (0 if m.get("is_default") else 1, m.get("id") or 0),
    )



    # 6) Render the payment page (your modal/JS can post to /api/pay/timeout/)
    return render(request, "payment.html", {
        "amount": round(total_payable, 2),
        "currency": "INR",
        "payment": payment_payload,
        "order": orders_data,
        # right-side price card values used by your template
        "item_count": item_count,
        "cart_total": cart_total,
        "shipping_fee": shipping_fee,
        "platform_fee": platform_fee,
        "total_payable": total_payable,
        "saved_methods": saved_methods,
        "saved_upis": saved_upis,       
        "saved_cards": saved_cards,
        "user_id": user_id,
        "payments_base": payment_url.rstrip('/'),
    })


# --- one-time toast helper -----------------------------------------------
def set_toast(request, text: str, kind: str = "success") -> None:
    """
    Save a single-use toast payload in session.
    kind: "success" | "error"
    """
    request.session["__toast"] = {"text": text, "kind": kind}
    request.session.modified = True


@ensure_csrf_cookie
@require_POST
def payment_success(request):
    if request.method != "POST":
        return redirect("pay_start")
    """
    Called by the payment handler when a payment is successful.
    Consumes the '__pending_order__' snapshot, creates the order,
    clears the cart, cleans session, then redirects to /api/vieworders/
    with a session 'flash' toast (no query params, no messages framework).
    """
    orders_data = request.session.get('__pending_order__')

    # If we lost the snapshot, show an error toast on vieworders
    if not orders_data:
        set_toast(request, "No pending payment found.", "error")
        return redirect(reverse("vieworders"))

    # --- compute / ensure final totals ---
    summary = orders_data.get("summary") or {}

    def f(x):
        try:
            return float(x or 0)
        except Exception:
            return 0.0

    final_total = summary.get("total_payable") or summary.get("final_total")
    final_total = f(final_total) if final_total is not None else (
        f(summary.get("cart_total")) + f(summary.get("shipping_fee")) + f(summary.get("platform_fee"))
    )

    summary.update({
        "final_total": final_total,
        "total_payable": final_total if summary.get("total_payable") is None else f(summary.get("total_payable")),
    })
    orders_data["summary"] = summary
    orders_data["total_amount"] = final_total

     # --- save user's UPI / Card (MOCK safe) ---
    try:
        user_id = _get_current_user_id(request)
        if user_id:
            # Saved method chosen? (radio)
            picked_id = request.POST.get('saved_method_id')
            picked_tp = request.POST.get('saved_method_type')
            if picked_id and picked_tp:
                # Nothing to save; user used an existing saved method
                pass
            else:
                # UPI from manual entry
                save_upi = (request.POST.get('save_upi') == '1')
                upi_vpa  = (request.POST.get('upi_vpa') or '').strip()
                if save_upi and upi_vpa:
                    def _mask_upi(v):
                        if '@' not in v: return 'UPI ••••'
                        name, dom = v.split('@', 1)
                        head = (name[:3] if len(name) >= 3 else name[:1]) + '****'
                        return f"{head}@{dom}"
                    masked = _mask_upi(upi_vpa)

                    # Is it the first UPI for this user? (make default)
                    try:
                        have_upi = requests.get(
                            f"{payment_url.rstrip('/')}/payment-methods/",
                            params={"user_id": user_id},
                            cookies=request.COOKIES, timeout=5
                        )
                        is_first_upi = True
                        if have_upi.ok:
                            for row in (have_upi.json() or []):
                                if (row or {}).get("method_type") == "upi":
                                    is_first_upi = False
                                    break
                    except Exception:
                        is_first_upi = False

                    resp = requests.post(
                        f"{payment_url.rstrip('/')}/payment-methods/",
                        json={
                            "user_id": user_id,
                            "provider": "mock",
                            "method_type": "upi",
                            "upi_vpa": upi_vpa,
                            "upi_provider_name": None,
                            "masked_display": masked,
                            "consented": True,
                            "is_default": is_first_upi,
                        },
                        cookies=request.COOKIES,
                        headers={"X-CSRFToken": request.COOKIES.get("csrftoken", "")},
                        timeout=6,
                    )
                    if not resp.ok:
                        print("SAVE UPI FAILED:", resp.status_code, resp.text[:300])


                # Card from manual entry (mock tokenization)
                save_card = (request.POST.get('save_card') == '1')
                last4     = (request.POST.get('card_last4') or '').strip()[:4]
                brand     = (request.POST.get('card_brand') or 'CARD').strip().upper()
                exp_month = request.POST.get('card_exp_month')
                exp_year  = request.POST.get('card_exp_year')
                masked_d  = request.POST.get('card_masked')
                card_holder_name = (request.POST.get('card_holder_name') or '').strip()

                if save_card and last4:
                    try:
                        exp_month = int(exp_month) if exp_month else None
                    except:
                        exp_month = None
                    try:
                        exp_year = int(exp_year) if exp_year else None
                    except:
                        exp_year = None

                    if not masked_d:
                        masked_d = f"{brand} •••• {last4}"

                    mock_token = f"mock_{int(time.time() * 1000)}_{last4}"

                    # Is it the first CARD for this user? (make default)
                    try:
                        have_card = requests.get(
                            f"{payment_url.rstrip('/')}/payment-methods/",
                            params={"user_id": user_id},
                            cookies=request.COOKIES, timeout=5
                        )
                        is_first_card = True
                        if have_card.ok:
                            for row in (have_card.json() or []):
                                if (row or {}).get("method_type") == "card":
                                    is_first_card = False
                                    break
                    except Exception:
                        is_first_card = False

                    resp = requests.post(
                        f"{payment_url.rstrip('/')}/payment-methods/",
                        json={
                            "user_id": user_id,
                            "provider": "mock",
                            "method_type": "card",
                            "token": mock_token,
                            "card_brand": brand,
                            "last4": last4,
                            "exp_month": exp_month or None,
                            "exp_year":  exp_year or None,
                            "card_holder_name": card_holder_name,
                            "masked_display": masked_d,
                            "consented": True,
                            "is_default": is_first_card,
                        },
                        cookies=request.COOKIES,
                        headers={"X-CSRFToken": request.COOKIES.get("csrftoken", "")},
                        timeout=6,
                    )
                    if not resp.ok:
                        print("SAVE CARD FAILED:", resp.status_code, resp.text[:300])

    except Exception:
        pass


    # --- mark statuses for the Orders service ---
    orders_data["status"] = "PAID"                # internal status
    orders_data["order_status"] = "Placed"        # display-friendly
    orders_data["payment_status"] = "SUCCESS"
    orders_data["payment"] = request.session.get("__pending_payment__", {})

    # --- create order in Orders service ---
    try:
        resp = requests.post(
            f"{order_url.rstrip('/')}/api/placeorder/",
            data={"order": json.dumps(orders_data)},
            cookies=request.COOKIES,
            timeout=12
        )
        if not resp.ok:
            set_toast(request, "Order creation failed after payment. Contact support.", "error")
            return redirect(reverse("vieworders"))
    except Exception:
        set_toast(request, "Unexpected error while finalizing order.", "error")
        return redirect(reverse("vieworders"))

    # --- best-effort clear cart ---
    try:
        requests.post(f"{cart_url.rstrip('/')}/api/clearcart/", data={}, cookies=request.COOKIES, timeout=8)
    except Exception:
        pass

    # --- clean session state ---
    for k in ("__pending_order__", "__pending_payment__", "checkout_snapshot"):
        request.session.pop(k, None)
    request.session.modified = True

    # --- success toast on /api/vieworders/ ---
    set_toast(request, "Payment successful! Order placed.", "success")
    print("PAY POST KEYS:", list(request.POST.keys()))
    print("Saved-method POST attempted for user:", user_id)
    print("SAVE FLAGS -> save_upi:", request.POST.get('save_upi'),
      "upi_vpa:", request.POST.get('upi_vpa'),
      "save_card:", request.POST.get('save_card'),
      "last4:", request.POST.get('card_last4'),
      "brand:", request.POST.get('card_brand'),
      "exp:", request.POST.get('card_exp_month'), request.POST.get('card_exp_year'))
    return redirect(reverse("vieworders"))



def get_payment_breakdown(order_id: int, request) -> dict:
    """
    Returns:
      {
        "headline": "Card – VISA ****1234",
        "attempts": [ ...normalized rows... ],
        "paid_amount": 1799.0
      }
    """
    attempts = []

    # A) Try your Payments service by order_id
    try:
        r = requests.get(f"{payment_url}/api/payments/by-order/", params={"order_id": order_id},
                         cookies=request.COOKIES, timeout=8)
        if r.ok:
            for row in (r.json() or []):
                attempts.append(normalize_payment_attempt(row))
    except Exception:
        pass

    # B) Fallback: sometimes Orders snapshot carries a payment dict/list
    try:
        r2 = requests.get(f"{order_url}/api/orders/payment-info/", params={"order_id": order_id},
                          cookies=request.COOKIES, timeout=6)
        if r2.ok:
            js = r2.json() or {}
            raw_list = js.get("attempts") or js.get("payments") or ([js] if js else [])
            for row in raw_list:
                attempts.append(normalize_payment_attempt(row))
    except Exception:
        pass
    # Dedup by txn_id + amount
    seen = set()
    uniq = []
    for a in attempts:
        key = (a.get("txn_id"), round(a.get("amount", 0), 2), a.get("mode"))
        if key not in seen:
            seen.add(key); uniq.append(a)
    attempts = uniq

    headline = headline_from_attempts(attempts)
    paid_amount = sum(a.get("amount",0) for a in attempts if a["status"]=="success")
    return {"headline": headline, "attempts": attempts, "paid_amount": float(paid_amount)}


@csrf_exempt
def payment_timeout(request):
    if request.method != 'POST':
        return JsonResponse({'ok': False, 'error': 'method_not_allowed'}, status=405)

    orders_data = request.session.get('__pending_order__')
    if not orders_data:
        # still give the user feedback next time they hit vieworders
        set_toast(request, "Payment not successful. Please contact your bank for any money deducted.", "error")
        return JsonResponse({'ok': False, 'error': 'no_pending_order'}, status=400)

    # compute final total if not stored
    summary = orders_data.get('summary', {}) or {}
    final_total = float(summary.get("final_total") or (
        float(summary.get("cart_total") or 0) +
        float(summary.get("shipping_fee") or 0) +
        float(summary.get("platform_fee") or 0)
    ))
    summary["final_total"] = final_total
    orders_data["summary"] = summary
    orders_data["total_amount"] = final_total
    orders_data["status"] = "PAYMENT_FAILED"

    try:
        r = requests.post(
            f"{order_url}/api/log_failed_order/",
            data={"order": json.dumps(orders_data)},
            cookies=request.COOKIES,
            timeout=10
        )
        if not r.ok:
            # even if logging failed, show the toast on next vieworders
            set_toast(request, "Payment not successful. Please contact your bank for any money deducted.", "error")
            return JsonResponse({'ok': False, 'error': 'orders_service_reject'}, status=502)
    except Exception as e:
        set_toast(request, "Payment not successful. Please contact your bank for any money deducted.", "error")
        return JsonResponse({'ok': False, 'error': 'orders_service_unreachable'}, status=502)

    # set the toast so the next navigation shows it
    set_toast(request, "Payment not successful. Please contact your bank for any money deducted.", "error")
    return JsonResponse({'ok': True})


def payment_failure(request):
    # User explicitly cancelled / provider returned failure
    set_toast(request, "Payment cancelled. No money was taken.", "error")
    return redirect(reverse("vieworders"))

@require_GET
def pay_flash_success(request):
    messages.success(request, "Payment successful! Order placed.")
    return redirect(reverse("vieworders"))

@require_GET
def pay_flash_fail(request):
    messages.error(request, "Payment not successful. Please contact your bank for any money deducted.")
    return redirect(reverse("vieworders"))




# ORDER SERVICE CODE

def _get_current_user_id(request):
    try:
        data = requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES, timeout=8).json()
        return data.get('user_id')
    except Exception:
        return None
    

def _get_my_review_id(product_id, request):
    try:
        r = requests.get(
            f'{review_url}/api/reviews/mine/',
            params={'product_id': product_id},
            cookies=request.COOKIES, timeout=6
        )
        if r.ok:
            data = r.json() or {}
            rv = data.get('review')
            return rv.get('review_id') if rv else None
    except Exception:
        pass
    return None



def _to_epoch(value):
    """Return POSIX seconds for datetime/ISO string; 0 if unknown."""
    if value is None:
        return 0
    if hasattr(value, "tzinfo"):
        try:
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return int(value.timestamp())
        except Exception:
            return 0
    if isinstance(value, str):
        s = value.strip()
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            return int(datetime.fromisoformat(s).timestamp())
        except Exception:
            return 0
    return 0

# utils in views.py
def _simulate_eta(placed_ts: int, seed=None) -> int:
    """
    Deterministic ETA:
      base = placed_ts (or now)
      + 2..6 days and 0..12 hours chosen from a seeded RNG
    """
    now = int(datetime.now(tz=timezone.utc).timestamp())
    base = placed_ts or now

    # stable seed from order identity
    if seed is None:
        seed = base
    r = random.Random(hash(seed) & 0xffffffff)

    add_days  = r.randint(2, 6)
    add_hours = r.randint(0, 12)
    return base + add_days*86400 + add_hours*3600


def vieworders(request):
    if request.GET.get("placed") == "1":
        messages.success(request, "Payment successful! Order placed.")
    if request.GET.get("not_placed") == "1" or request.GET.get("failed") == "1" or request.GET.get("timeout") == "1":
        messages.error(request, "Payment not successful. Please contact your bank for any money deducted.")

    # ---------------- fetch ----------------
    r = requests.get(f'{order_url}/api/placeorder/', cookies=request.COOKIES, timeout=6)
    if r.status_code == 401:
        return render(
            request,
            "vieworder.html",
            {"order_data": [], "page_obj": None, "session_expired": True}
        )
    if not r.ok:
        return render(request, "vieworder.html", {"order_data": [], "page_obj": None})

    order_data = r.json()
    if isinstance(order_data, str):
        try:
            order_data = json.loads(order_data)
        except json.JSONDecodeError:
            order_data = {}

    raw_orders = order_data.get('orderlist', []) or []

    # ---------------- normalize/enrich ----------------
    now_ts = int(datetime.now(tz=timezone.utc).timestamp())

    # NEW: per-request caches (avoid calling the same endpoints repeatedly)
    product_cache: dict[str, dict] = {}
    review_cache: dict[str, typing.Optional[int]] = {}

    for idx, order in enumerate(raw_orders):
        items = order.get('order_items', []) or []
                # preview for the list card (first item thumb/name and “+N more”)
        if items:
            _first = items[0]
            order['preview_image'] = _first.get('image', '')
            order['preview_name']  = _first.get('product_name') or 'Item'
            order['preview_more']  = max(0, len(items) - 1)
        else:
            order['preview_image'] = ''
            order['preview_name']  = 'Items'
            order['preview_more']  = 0


        placed_ts = _to_epoch(order.get('placed_time'))
        order['placed_ts'] = placed_ts

        status = (order.get('order_status') or '').strip() or 'Placed'

        # keep numeric id for URL reversing
        raw_id = order.get('order_id')
        try:
            order_pk = int(raw_id)
        except (TypeError, ValueError):
            order_pk = None
        order['order_pk'] = order_pk

        # use real code from Order service for display
        order['display_code'] = (order.get('order_code') or '').strip()

        # ETA/status (unchanged)
        seed = order.get('order_code') or order.get('order_id') or placed_ts or idx
        eta_ts = _simulate_eta(placed_ts, seed)        
        special = {'payment failed', 'cancelled', 'returned', 'order not placed'}
        if status.lower() in special:
            # keep the special status; no ETA
            order['order_status'] = status
            order['delivery_eta_ts'] = 0
        else:
            # normal shipping logic
            order['order_status'] = 'Delivered' if eta_ts <= now_ts else 'On the way'
            order['delivery_eta_ts'] = int(eta_ts)

        # ---- totals (your existing logic, kept) ----
        cart_total = 0.0
        for it in items:
            try:
                line_total = it.get('total_price')
                if line_total is None:
                    qty = float(it.get('quantity') or 1)
                    unit = it.get('price')
                    if unit is None:
                        unit = (it.get('product') or {}).get('price')
                    unit = float(unit or 0)
                    line_total = qty * unit
                cart_total += float(line_total or 0)
            except (TypeError, ValueError):
                pass

        shipping_fee = 0.0 if cart_total == 0 else (0.0 if cart_total >= 1500 else 100.0)
        platform_fee = 0.0 if cart_total == 0 else float(PLATFORM_FEE_RS)

        summary = order.get('summary', {}) or {}
        final_total = summary.get('final_total') or summary.get('total_payable')
        try:
            final_total = float(final_total)
        except (TypeError, ValueError):
            final_total = cart_total + shipping_fee + platform_fee

        summary.update({
            "item_count": len(items),
            "cart_total": float(cart_total),
            "shipping_fee": float(shipping_fee),
            "platform_fee": float(platform_fee),
            "total_payable": float(cart_total + shipping_fee + platform_fee),
            "final_total": float(final_total),
        })
        order['summary'] = summary
        order['total_amount'] = float(final_total)

        # per-item enrichment (now with request-level caching)
        for item in items:
            pid_raw = item.get("product_id")
            if pid_raw is None:
                continue
            pid = str(pid_raw)

            # --- product cache: only fetch each product once per request ---
            if pid not in product_cache:
                try:
                    resp = requests.get(
                        f'{product_url}/api/productview/{pid}/',
                        cookies=request.COOKIES,
                        timeout=4
                    )
                    product_cache[pid] = resp.json() if resp.ok else {}
                except Exception:
                    product_cache[pid] = {}

            pd = product_cache.get(pid, {}) or {}
            item['product_name'] = pd.get('product_name') or item.get('product_name') or 'Unknown product'
            img = pd.get('image') or ''
            item['image'] = img.replace('http://152.14.0.14', 'http://127.0.0.1')

            # --- review cache: only check "mine" once per product per request ---
            if pid not in review_cache:
                review_cache[pid] = _get_my_review_id(pid, request)
            item['my_review_id'] = review_cache[pid]

    # ---------------- paginate (fast UI) ----------------
    paginator = Paginator(raw_orders, 50)  # 50 orders/page
    page_obj = paginator.get_page(request.GET.get("page", 1))

    # --- NEW: session toast + collected Django messages ---
    flash_toast = request.session.pop("__toast", None)

    # --- Django messages (set by /api/pay/flash/* or anywhere else)
    from django.contrib import messages as dj
    dj_messages = [{"text": m.message, "tags": m.tags} for m in dj.get_messages(request)]

    return render(request, "vieworder.html", {
        "order_data": list(page_obj.object_list),
        "page_obj": page_obj,
        "session_expired": False,
        "flash_toast": flash_toast,      
        "dj_messages": dj_messages,
    })



def vieworderdetails(request, order_pk: int):
    """
    Render the details page for a single order.
    - order_pk is the DB order_id (integer) saved by your Orders service.
    - Enriches with order items, product info, and the shipping address.
    - Adds recipient_name/phone/address_label/shipping_address for the template.
    """
    # top of vieworderdetails, after the docstring
    if request.GET.get("simulate_expired") == "1":
        return render(request, "vieworderdetails.html", {
            "order": {"order_id": order_pk, "order_items": []},
            "item": {},
            "status_ok_for_invoice": False,
            "session_expired": True,
        })

    session_expired = False  # <— new
    user, session_expired = get_user_from_request(request)

    # --- 1) Base order ---
    r = None
    try:
        r  = requests.get(f'{order_url}/api/orders/orderdata/',  params={'order_id': order_pk}, cookies=request.COOKIES, timeout=10)
    except Exception:
        pass
    print(
            "orderdata status:", getattr(r, "status_code", None),
            "cookies_present:", bool(request.COOKIES),
        )

    # If cookie/session expired, show the page with login modal flag (hard 401/403 from Orders)
    if r is not None and r.status_code in (401, 403):
        return render(
            request,
            "vieworderdetails.html",
            {
                "order": {"order_id": order_pk, "order_items": []},
                "item": {},
                "status_ok_for_invoice": False,
                "session_expired": True,   
            },
        )

    if not r or not r.ok:
        raise Http404("Order not found")

    order = r.json() or {}
    if not order or int(order.get('order_id', 0)) != int(order_pk):
        raise Http404("Order not found")
    jwt_tok = request.COOKIES.get('jwt') or ''
    print(
        "jwt_present:", bool(jwt_tok),
        "orders_status:", getattr(r, "status_code", None),
    )


    pii_missing = not any([
        (order.get('shipping_address') or '').strip(),
        (order.get('recipient_name')  or '').strip(),
        (order.get('recipient_phone') or '').strip(),
    ])
    if pii_missing:
        session_expired = True

    # Soft heuristic: if we don’t have typical auth cookies, consider the session expired
    if not (request.COOKIES.get("sessionid") or request.COOKIES.get("jwt") or request.COOKIES.get("access")):
        session_expired = True

    order['display_code'] = (order.get('order_code') or '').strip()

    # --- 2) Order items ---
    items = []
    try:
        ri = requests.get(f'{order_url}/api/orders/orderitems/', params={'order_id': order_pk},
                        cookies=request.COOKIES, timeout=10)
        if ri.ok:
            items = ri.json() or []
    except Exception:
        pass

    # NEW: per-request caches so we don't call the same endpoints repeatedly
    product_cache: dict[str, dict] = {}
    review_cache: dict[str, typing.Optional[int]] = {}

    # Enrich items with product data **and** "my review" status
    for it in items:
        pid = it.get('product_id')
        if not pid:
            continue
        pid_str = str(pid)

        # --- product (cached) ---
        if pid_str not in product_cache:
            try:
                pr = requests.get(f'{product_url}/api/productview/{pid_str}/',
                                cookies=request.COOKIES, timeout=8)
                product_cache[pid_str] = pr.json() if pr.ok else {}
            except Exception:
                product_cache[pid_str] = {}

        pd = product_cache.get(pid_str, {}) or {}
        it['product_name'] = pd.get('product_name') or it.get('product_name') or 'Unknown product'
        img = pd.get('image') or ''
        it['image'] = img.replace('http://152.14.0.14', 'http://127.0.0.1:8001')

        # --- NEW: find the logged-in user's review id for this product (cached) ---
        if pid_str not in review_cache:
            review_cache[pid_str] = _get_my_review_id(pid_str, request)
        it['my_review_id'] = review_cache[pid_str]

    order['order_items'] = items

    # --- Price summary so the template has per-row numbers ---
    cart_total = 0.0
    for it in items:
        # prefer a ready line total; else compute qty * unit
        line_total = it.get('total_price')
        if line_total is None:
            try:
                qty  = float(it.get('quantity') or it.get('qty') or 1)
                unit = it.get('final_price') or it.get('price') \
                    or (it.get('product') or {}).get('price') \
                    or it.get('amount') or 0
                line_total = float(unit) * qty
            except Exception:
                line_total = 0.0
        cart_total += float(line_total or 0)

    shipping_fee = 0.0 if cart_total == 0 else (0.0 if cart_total >= 1500 else 100.0)
    platform_fee = 0.0 if cart_total == 0 else float(PLATFORM_FEE_RS)

    s = (order.get('summary') or {}).copy()
    s.update({
        "item_count": len(items),
        "cart_total": float(cart_total),
        "shipping_fee": float(shipping_fee),
        "platform_fee": float(platform_fee),
        "total_payable": float(cart_total + shipping_fee + platform_fee),
    })
    order['summary'] = s
    # keep total_amount in sync for older templates
    order['total_amount'] = float(s.get('final_total', s['total_payable']))

    pb = get_payment_breakdown(order_pk, request)
    order["payment_mode_label"] = pb["headline"]          
    order["payment_attempts"]   = pb["attempts"]          
    order["paid_amount"]        = pb["paid_amount"] or order.get("total_amount")

    # >>> ADD THESE 5 LINES <<<
    item = items[0] if items else {
        "product_name": "Item",
        "image": "",
        "price": order.get("total_amount", 0),
    }

   # --- 3) Shipping address (prefer values from address_id the user chose) ---
    def _fmt_address(a: dict) -> str:
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

    # Snapshot from the order (may be stale)
    recipient_name  = (order.get('recipient_name') or order.get('ship_to_name') or "").strip()
    recipient_phone = (order.get('recipient_phone') or order.get('ship_to_phone') or "").strip()
    address_label   = (order.get('address_label') or 'Home').strip()
    shipping_addr   = (order.get('shipping_address') or "").strip()

    # If an address_id is present, resolve it and OVERRIDE all four fields
    def _addr_id_of(d: dict) -> str:
        for k in ('address_id', 'id', 'addressId', 'aid'):
            v = d.get(k)
            if v is not None:
                return str(v)
        return ''

    addr_id = order.get('address_id') or (order.get('address') or {}).get('address_id')
    addr_obj = None
    addresses = []
    if addr_id:
        try:
            ar = requests.get(f'{user_url}/api/getaddress/', cookies=request.COOKIES, timeout=10)
            if ar.ok:
                addresses = (ar.json() or {}).get('addresses', []) or []
                addr_obj = next((x for x in addresses if _addr_id_of(x) == str(addr_id)), None)
        except Exception:
            addr_obj = None

    # Optional: debug what we matched
    try:
        print("order.address_id =", addr_id)
        print("address_book_ids =", [_addr_id_of(a) for a in addresses])
        print("matched_addr =", bool(addr_obj))
    except Exception:
        pass

    if addr_obj:
        # overwrite (do not “only if missing”)
        recipient_name  = (
            addr_obj.get('customer_name') or addr_obj.get('username') or addr_obj.get('name')
            or f"{addr_obj.get('firstname','')} {addr_obj.get('lastname','')}".strip()
            or recipient_name
        )
        recipient_phone = (
            addr_obj.get('customer_phone') or addr_obj.get('phone') or addr_obj.get('mobile')
            or recipient_phone
        )
        address_label   = (addr_obj.get('address_type') or addr_obj.get('type') or address_label or 'Home')
        shipping_addr   = _fmt_address(addr_obj) or shipping_addr


    # Fall back once more to the embedded address dict if nothing resolved
    if not shipping_addr and isinstance(order.get('address'), dict):
        shipping_addr = _fmt_address(order['address'])

    # Write back for the template
    order['recipient_name']   = recipient_name
    order['customer_name']    = recipient_name
    order['recipient_phone']  = recipient_phone
    order['shipping_address'] = shipping_addr
    order['address_label']    = address_label

    # --- Who can access (strip + modal) -----------------------------------------
    def _digits(s: str) -> str:
        return "".join(ch for ch in (s or "") if ch.isdigit())

    def _norm(s: str) -> str:
        return (s or "").strip().lower()

    # 1) Try to get the logged-in user's info
    buyer_phone = (order.get("buyer_phone") or request.COOKIES.get("phone") or "").strip()
    buyer_name  = ""

    if not buyer_phone or not buyer_name:
        try:
            u = requests.get(f"{user_url}/api/userview/", cookies=request.COOKIES, timeout=6)
            # If this user endpoint says 401/403, mark as expired (for the modal), but keep page usable
            if u.status_code in (401, 403):
                session_expired = True
            elif u.ok:
                uj = u.json() or {}
                buyer_phone = (
                    (buyer_phone or uj.get("phone") or uj.get("mobile") or
                     uj.get("customer_phone") or uj.get("contact") or uj.get("tel") or "")
                    .strip()
                )
                buyer_name = (uj.get("username") or uj.get("name") or uj.get("customer_name") or "")
        except Exception:
            # network error: don’t crash; keep whatever we have
            pass

    # last-ditch fallbacks (if your Orders service carries who placed the order)
    buyer_phone = (buyer_phone or order.get("login_phone") or order.get("placed_by_phone") or "").strip()
    buyer_name  = (buyer_name  or order.get("login_name")  or order.get("placed_by_name")  or "").strip()

    recipient_phone = (order.get("recipient_phone") or "").strip()
    recipient_name  = (order.get("recipient_name")  or "").strip()

    # 2) placed-for-other?
    phones_differ = bool(_digits(buyer_phone) and _digits(recipient_phone) and
                        _digits(buyer_phone) != _digits(recipient_phone))
    names_differ  = bool(_norm(buyer_name) and _norm(recipient_name) and
                        _norm(buyer_name) != _norm(recipient_name))

    placed_for_other = phones_differ or (not _digits(buyer_phone) and names_differ)

    # 3) shared list (only other people; don’t add buyer)
    existing = list(order.get("shared_numbers") or [])
    shared = list(existing)
    if placed_for_other and recipient_phone and recipient_phone not in shared:
        shared.append(recipient_phone)

    order["shared_numbers"]    = shared
    order["buyer_phone"]       = buyer_phone  # expose for template labelling if needed
    order["access_phone"]      = recipient_phone if placed_for_other else (shared[0] if shared else "")
    order["show_access_strip"] = bool(order["access_phone"])
    order["access_remove_api"] = f"/api/orders/{order_pk}/access/remove/"

    print("buyer_phone=", buyer_phone,
        "recipient_phone=", recipient_phone,
        "buyer_name=", buyer_name,
        "recipient_name=", recipient_name,
        "placed_for_other=", placed_for_other,
        "access_phone=", order["access_phone"],
        "show_access_strip=", order["show_access_strip"],
        "shared_numbers=", order["shared_numbers"])

    # --- 4) Timeline / timestamps (safe defaults) ---
    now_ts = int(datetime.now(tz=timezone.utc).timestamp())

    def _to_epoch(v):
        try:
            if v is None or v == "":
                return 0
            if isinstance(v, (int, float)):
                n = int(v)
                return n // 1000 if n > 1_000_000_000_000 else n  # ms -> s
            if isinstance(v, str):
                s = v.strip()
                if not s:
                    return 0
                if s.endswith("Z"):
                    s = s[:-1] + "+00:00"
                return int(datetime.fromisoformat(s).timestamp())
            if hasattr(v, "timestamp"):
                return int(v.timestamp())
        except Exception:
            pass
        return 0

    def _pick(d, *keys):
        for k in keys:
            if k in d and d[k] not in (None, "", 0):
                return d[k]
        return 0

    # normalize status early (you were missing status_lc)
    status    = (order.get("order_status") or "").strip()
    status_lc = status.lower()

    # placed/created/confirmed
    placed_ts = _to_epoch(_pick(order, "placed_ts", "placed_time", "order_time", "created_at"))
    order["placed_ts"]    = placed_ts or now_ts
    order["created_ts"]   = _to_epoch(_pick(
        order, "created_ts","created_time","created_at","created_on",
        "order_date","order_created","order_time","placed_time"
    )) or order["placed_ts"]
    order["confirmed_at"] = order["placed_ts"]  # treat placed as confirmed

    # deterministic seed so ETA doesn't change on refresh
    seed = order.get('order_code') or order_pk or order.get('placed_ts') or now_ts

    # try to pull delivered time from many places (order and first item)
    first_item = (order.get("order_items") or ([item] if item else []))[:1]
    first      = first_item[0] if first_item else {}

    delivered_ts = _to_epoch(_pick(
        order, "delivered_at","delivered_on","delivery_date","actual_delivery","deliveredTime"
    )) or _to_epoch(_pick(
        first, "delivered_at","delivered_on","delivery_date","actual_delivery","deliveredTime"
    ))

    # if marked delivered but timestamp missing, fabricate a sane one
    if status_lc == "delivered" and not delivered_ts:
        delivered_ts = order["confirmed_at"] + 2*86400

    order["delivered_at"] = int(delivered_ts or 0)

    special = {"payment failed", "order not placed", "not yet placed", "cancelled", "returned"}

    # Prefer ETA from API (order or first item); else simulate deterministically
    eta_from_api = _to_epoch(_pick(
        order, "delivery_eta","expected_delivery","delivery_by","eta","promise_date"
    )) or _to_epoch(_pick(
        first, "delivery_eta","expected_delivery","delivery_by","eta","promise_date"
    ))

    # IMPORTANT: your _simulate_eta must accept a seed and use random.Random(seed)
    order["delivery_eta_ts"] = 0 if status_lc in special else int(
        eta_from_api or _simulate_eta(order["confirmed_at"], seed)
    )

    # Final delivered flag from real timestamp
    order["is_delivered"] = bool(order["delivered_at"] and order["delivered_at"] <= now_ts)

    # If not delivered but ETA has passed, promote to delivered so the detail page
    # matches the list page (and dates stay stable)
    if not order["is_delivered"] and status_lc not in special:
        if order["delivery_eta_ts"] and order["delivery_eta_ts"] <= now_ts:
            order["is_delivered"] = True

    bad = {'payment failed', 'order not placed', 'not yet placed'}
    status_ok_for_invoice = (str(order.get('order_status', '')).strip().lower() not in bad)

    # --- Who can access (strip + modal) ---
    # --- Manage "who can access" (strip + modal) -------------------------------
    def _norm(s):
        return (s or "").strip().lower()

    buyer_phone     = (order.get("buyer_phone") or request.COOKIES.get("phone") or "").strip()
    recipient_phone = (order.get("recipient_phone") or "").strip()

    # Gate by order status: hide strip for failed / not-placed
    order_status  = (order.get("order_status") or "").strip().lower()
    bad_statuses  = {"payment failed", "order not placed", "not yet placed"}
    order_active  = order_status not in bad_statuses

    # Build shared numbers (dedup)
    def _uniq(seq):
        out = []
        for s in seq:
            s = (s or "").strip()
            if s and s not in out:
                out.append(s)
        return out

    existing = list(order.get("shared_numbers") or [])

    # Seed recipient only when buyer != recipient
    seed = []
    if buyer_phone and recipient_phone and _norm(buyer_phone) != _norm(recipient_phone):
        seed.append(recipient_phone)

    shared = _uniq([*seed, *existing])
    order["shared_numbers"] = shared

    # Phone to show in the strip
    access_phone = shared[0] if shared else (
        recipient_phone if (buyer_phone and _norm(buyer_phone) != _norm(recipient_phone)) else ""
    )
    order["access_phone"] = access_phone
    # SHOW only if order is active AND we actually have a phone to show
    order["show_access_strip"] = bool(order_active and access_phone)
    # API for removal
    order["access_remove_api"] = f"/api/orders/{order_pk}/access/remove/"
    # (Optional) expose buyer so the modal can tag "You"
    order["buyer_phone"] = buyer_phone

    ctx = { "order": order, "item": item, "status_ok_for_invoice": status_ok_for_invoice,
            "session_expired": session_expired }
    resp = render(request, "vieworderdetails.html", ctx)
    resp["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    
    return resp
   


@require_POST
def remove_access_number(request, order_id):
    try:
        payload = json.loads(request.body or "{}")
        phone = (payload.get("phone") or "").strip()
        if not phone:
            return HttpResponseBadRequest("phone missing")

        remaining = 0  # set to len(order.shared_numbers) when using a real model
        return JsonResponse({"ok": True, "remaining": remaining})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)
    

# --- add these imports near the top of views.py ---
import os
import shutil
import requests
import pdfkit
from tempfile import NamedTemporaryFile

from django.http import HttpResponse, Http404
from django.template.loader import render_to_string
from django.templatetags.static import static
from django.contrib.staticfiles import finders
from django.utils import timezone
from datetime import datetime
# user_url, product_url, order_url, PLATFORM_FEE_RS must already be defined in your settings/imports


def invoice_pdf(request, order_pk: int):
    """Build and download invoice as <order_code>.pdf, with structured addresses (wkhtmltopdf-safe)."""

    # ---------- 1) Fetch core order ----------
    try:
        r = requests.get(
            f"{order_url}/api/orderdata/",
            params={"order_id": order_pk},
            cookies=request.COOKIES,
            timeout=10,
        )
    except Exception:
        r = None
    if not r or not r.ok:
        raise Http404("Order not found")
    order = r.json() or {}
    if int(order.get("order_id", 0)) != int(order_pk):
        raise Http404("Order not found")

    order_code = (order.get("order_code") or f"ORDER_{order_pk}").strip()

    # ---------- 2) Fetch items ----------
    items = []
    try:
        ri = requests.get(
            f"{order_url}/api/orderitems/",
            params={"order_id": order_pk},
            cookies=request.COOKIES,
            timeout=10,
        )
        if ri.ok:
            items = ri.json() or []
    except Exception:
        pass

    # Normalize items a bit for the template
    norm_items = []
    for it in items:
        pid = it.get("product_id")
        name = it.get("product_name") or "Item"
        # enrich with product data if present
        if pid:
            try:
                pr = requests.get(f"{product_url}/api/productview/{pid}/",
                                  cookies=request.COOKIES, timeout=6)
                if pr.ok:
                    pd = pr.json() or {}
                    name = pd.get("product_name") or name
                    it.setdefault("price", pd.get("price") or 0)
            except Exception:
                pass

        qty = int(it.get("quantity") or it.get("qty") or 1)
        unit = float(it.get("final_price") or it.get("price") or it.get("amount") or 0)
        line_total = float(it.get("total_price") or (unit * qty))
        norm_items.append({
            "product_name": name,
            "qty": qty,
            "unit_price": unit,
            "line_total": line_total,
        })

    # ---------- 3) Dates ----------
    order_date_str = ""
    placed_raw = order.get("placed_time") or order.get("created_at") or order.get("order_time")
    if placed_raw:
        try:
            order_date_str = datetime.fromisoformat(placed_raw.replace("Z", "+00:00")).strftime("%d-%m-%Y")
        except Exception:
            order_date_str = ""
    invoice_date_str = timezone.now().strftime("%d-%m-%Y")

    # ---------- 4) Address helpers ----------
    def _split_address(addr: dict) -> dict:
        line1 = (
            addr.get("doorno") or addr.get("door_no") or addr.get("house_no")
            or addr.get("house") or addr.get("door") or ""
        )
        line2 = ", ".join(x for x in [
            addr.get("street") or addr.get("street1") or addr.get("address1"),
            addr.get("landmark") or addr.get("address2") or addr.get("street2"),
        ] if x)
        city = addr.get("city") or addr.get("district") or ""
        state = addr.get("state") or addr.get("province") or ""
        pincode = addr.get("pincode") or addr.get("postal_code") or addr.get("zip") or ""
        return {"line1": line1, "line2": line2, "city": city, "state": state, "pincode": pincode}

    recipient_name  = (order.get("recipient_name") or order.get("ship_to_name") or "").strip()
    recipient_phone = (order.get("recipient_phone") or order.get("ship_to_phone") or "").strip()

    # If address_id present -> pull from user service and override fields
    addr_id = order.get("address_id") or (order.get("address") or {}).get("address_id")
    addr_obj = None
    if addr_id:
        try:
            ar = requests.get(f"{user_url}/api/getaddress/", cookies=request.COOKIES, timeout=10)
            if ar.ok:
                addresses = (ar.json() or {}).get("addresses", []) or []
                addr_obj = next((x for x in addresses if str(x.get("address_id")) == str(addr_id)), None)
        except Exception:
            addr_obj = None

    bill = _split_address(addr_obj or (order.get("address") or {}))
    ship = bill  # same shipping; change if you later store separately

    # Prefer name/phone from address if available
    name_from_addr = (
        (addr_obj or {}).get("customer_name") or (addr_obj or {}).get("username")
        or (addr_obj or {}).get("name")
        or f"{(addr_obj or {}).get('firstname','')} {(addr_obj or {}).get('lastname','')}".strip()
    ).strip()
    phone_from_addr = (
        (addr_obj or {}).get("customer_phone") or (addr_obj or {}).get("phone")
        or (addr_obj or {}).get("mobile")
    )
    if name_from_addr:
        recipient_name = name_from_addr
    if phone_from_addr:
        recipient_phone = str(phone_from_addr)

    # ---------- 5) Summary totals (recompute like detail page) ----------
    cart_total = sum(i["line_total"] for i in norm_items)
    shipping_fee = 0.0 if cart_total == 0 else (0.0 if cart_total >= 1500 else 100.0)
    platform_fee = 0.0 if cart_total == 0 else float(PLATFORM_FEE_RS)

    # If API already had a final_total, you can prefer it; otherwise use our computed one.
    api_summary = order.get("summary") or {}
    grand_total = float(
        api_summary.get("final_total")
        or api_summary.get("total_payable")
        or (cart_total + shipping_fee + platform_fee)
    )
    amount_words = amount_in_words_rupees(grand_total, use_and=True)

     # --- Payment mode (very tolerant; works for old orders too) ---
    def _payment_headline(o: dict) -> str:
        pm  = (o.get("payment_mode") or o.get("paid_via") or o.get("payment_method") or "").lower()
        prov= (o.get("payment_provider") or o.get("gateway") or "").lower()
        cod = str(o.get("cod") or o.get("is_cod") or o.get("cash_on_delivery") or "").lower() in ("1","true","yes")
        if cod: return "Cash on Delivery"
        if "upi" in pm or "upi" in prov: return "UPI"
        if any(k in pm for k in ("card","debit","credit")): return "Card"
        if "net" in pm or "bank" in pm: return "Netbanking"
        if "wallet" in pm: return "Wallet"
        if "emi" in pm: return "EMI"
        if "gift" in pm: return "Gift Card"
        return "Online Payment"

    payment_mode_label = _payment_headline(order)


    # ---------- 6) Static file -> file:// URL (wkhtmltopdf safe) ----------
    def _file_url(static_rel_path: str) -> str:
        """Return a file:/// URL for a static asset (works in dev via staticfiles finders)."""
        abs_path = finders.find(static_rel_path)
        if not abs_path:
            return ""
        return "file:///" + os.path.abspath(abs_path).replace("\\", "/")

    # ---------- 7) Template context ----------
    ctx = {
        # branding / assets
        "logo_url": _file_url("images/novacart.png"),
        "font_regular": _file_url("fonts/Inter-Regular.ttf"),
        "font_medium":  _file_url("fonts/Inter-Medium.ttf"),
        "font_bold":    _file_url("fonts/Inter-Bold.ttf"),

        # seller block + invoice number
        "seller_name": "Novacart Pvt. Ltd.",
        "seller_pan": "AABCN0000X",
        "seller_gstin": "29AACFN0000Z1D",
        "invoice_no": order_code,

        # order meta
        "order_code": order_code,
        "order_date_str": order_date_str,
        "invoice_date_str": invoice_date_str,

        # addresses
        "billing_name": recipient_name,
        "billing_line1": bill["line1"],
        "billing_line2": bill["line2"],
        "billing_city": bill["city"],
        "billing_state": bill["state"],
        "billing_pincode": bill["pincode"],
        "billing_phone": recipient_phone,

        "shipping_name": recipient_name,
        "shipping_line1": ship["line1"],
        "shipping_line2": ship["line2"],
        "shipping_city": ship["city"],
        "shipping_state": ship["state"],
        "shipping_pincode": ship["pincode"],
        "shipping_phone": recipient_phone,

        # items and totals
        "items": norm_items,
        "summary": {
            "cart_total": cart_total,
            "shipping_fee": shipping_fee,
            "platform_fee": platform_fee,
            "total_payable": cart_total + shipping_fee + platform_fee,
            "final_total": grand_total,
        },
        "amount_in_words": f"{amount_words} Rupees only",
        "payment_mode_label": payment_mode_label, 
    }

    # ---------- 8) Render HTMLs ----------
    html = render_to_string("invoice.html", ctx)

    footer_html = render_to_string("invoice_footer.html", ctx)
    with NamedTemporaryFile(mode="w", suffix=".html", delete=False, encoding="utf-8") as f:
        f.write(footer_html)
        footer_path = f.name  # absolute path for --footer-html

    # ---------- 9) Build PDF ----------
    wkhtml_path = (
        shutil.which("wkhtmltopdf")
        or r"C:/Program Files/wkhtmltopdf/bin/wkhtmltopdf.exe"
        or r"C:/ProgramData/chocolatey/bin/wkhtmltopdf.exe"
    )
    config = pdfkit.configuration(wkhtmltopdf=wkhtml_path)

    pdf = pdfkit.from_string(
        html,
        False,
        configuration=config,
        options={
            "page-size": "A4",
            "encoding": "UTF-8",
            "enable-local-file-access": None,   # allow file:/// assets
            "margin-top": "14mm",
            "margin-bottom": "22mm",            # room for footer
            "margin-left": "14mm",
            "margin-right": "14mm",
            "footer-html": footer_path,         # stable, no overlap
            "footer-spacing": "-30",
        },
    )

    filename = f"{order_code}.pdf"
    resp = HttpResponse(pdf, content_type="application/pdf")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp





#REVIEW SERVICE CODE 

PAGE_SIZE = 3  

def _safe_str(x):
    return (x or "").strip() if isinstance(x, str) else ""

def _parse_dt(s: str):
    if not s:
        return datetime.min
    s = s.strip()
    fmts = ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]
    for f in fmts:
        try:
            return datetime.strptime(s, f)
        except Exception:
            pass
    return datetime.min

def _helpfulness(rv: Dict) -> int:
    return int(rv.get("like_count", 0))

def _fetch_all_reviews_for_product(request, product_id) -> List[Dict]:
    all_reviews, page = [], 1
    while True:
        try:
            r = requests.get(
                f"{review_url}/api/reviews/",
                params={"product_id": product_id, "page": page},
                cookies=request.COOKIES, timeout=10
            )
        except requests.RequestException:
            break
        if not r.ok:
            break
        data = r.json() if r.headers.get("content-type","").startswith("application/json") else {}
        chunk = data.get("results", [])
        if not chunk:
            break
        all_reviews.extend(chunk)
        pages = int(data.get("pages", page) or page)
        if page >= pages:
            break
        page += 1
    return all_reviews


def _is_review_entry(rv):
    """Count as a 'review' only if user added text or media."""
    if rv.get('title') or rv.get('body') or rv.get('image_url'):
        return True
    if isinstance(rv.get('image_urls'), list) and rv['image_urls']:
        return True
    if isinstance(rv.get('video_urls'), list) and rv['video_urls']:
        return True
    return False

def _build_page_links(cur_page, total_pages, make_url):
    """
    Return a list like:
    [{'n':1,'url':...,'is_current':False}, {'dots':True}, {'n':8,...}, {'n':9,...}, {'n':10,...}, {'dots':True}, {'n':114,...}]
    Rules:
      - If pages <= 9: show all
      - Else: 1 … (cur-2..cur+2) … last
      - Avoid duplicate dots when ranges touch
    """
    items = []

    def add_num(n):
        items.append({'n': n, 'url': make_url(n), 'is_current': (n == cur_page)})

    def add_dots():
        if not items or items[-1].get('dots'):
            return
        items.append({'dots': True})

    if total_pages <= 9:
        for n in range(1, total_pages + 1):
            add_num(n)
        return items

    # Always include first
    add_num(1)

    # Left dots?
    left_start = max(2, cur_page - 2)
    left_gap_needed = left_start > 2
    if left_gap_needed:
        add_dots()
    else:
        # If no gap, include pages up to left_start - 1 (i.e., page 2)
        for n in range(2, left_start):
            add_num(n)

    # Middle window
    mid_start = left_start
    mid_end = min(total_pages - 1, cur_page + 2)
    for n in range(mid_start, mid_end + 1):
        add_num(n)

    # Right dots?
    right_gap_needed = mid_end < (total_pages - 1)
    if right_gap_needed:
        add_dots()
    else:
        # If no gap, include the tail pages up to last-1
        for n in range(mid_end + 1, total_pages):
            add_num(n)

    # Always include last (if not already 1)
    if total_pages > 1:
        add_num(total_pages)

    return items


def _get_current_user_id(request):
    try:
        data = requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES, timeout=8).json()
        return data.get('user_id')
    except Exception:
        return None
    

def _has_purchased(request, product_id) -> bool:
    user_id = _get_current_user_id(request)
    if not user_id:
        return False
    try:
        r = requests.get(
            f'{order_url}/api/internal/has-purchased/',
            params={'user_id': str(user_id), 'product_id': str(product_id)},
            cookies=request.COOKIES,      # ← add this
            timeout=6
        )
        if r.ok:
            data = r.json()
            return bool(data.get('has_purchased'))
        return False
    except Exception:
        return False


def reviews_page(request, product_id):
    # product info
    product = requests.get(f'{product_url}/api/singleproduct/{product_id}/').json()

    # logged in user & can_review
    current_user_id = _get_current_user_id(request)
    can_review = bool(current_user_id and _has_purchased(request, product_id))

    # query params
    sort  = request.GET.get('sort', 'recent')  # recent | helpful | rating_desc | rating_asc
    stars = request.GET.get('stars')           # '1'..'5' or None
    valid_stars = {'1','2','3','4','5'}
    if stars not in valid_stars:
        stars = None

    # page param
    try:
        page = max(1, int(request.GET.get('page', '1')))
    except Exception:
        page = 1

    # stats for header
    stats = {}
    try:
        rs = requests.get(
            f'{review_url}/api/reviews/stats/',
            params={'product_id': product_id},
            cookies=request.COOKIES, timeout=10
        )
        if rs.ok:
            stats = rs.json()
    except Exception:
        pass

    # fetch all, then filter + sort
    all_reviews = _fetch_all_reviews_for_product(request, product_id)

    # Stars filter
    if stars:
        s = int(stars)
        all_reviews = [rv for rv in all_reviews if int(rv.get('rating', 0)) == s]
    rating_count = sum(1 for rv in all_reviews if int(rv.get('rating', 0)) > 0)
    review_count = sum(1 for rv in all_reviews if _is_review_entry(rv))

    # Sort
    if sort == 'rating_desc':
        all_reviews.sort(key=lambda rv: int(rv.get('rating', 0)), reverse=True)
    elif sort == 'rating_asc':
        all_reviews.sort(key=lambda rv: int(rv.get('rating', 0)))
    elif sort == 'helpful':
        all_reviews.sort(
            key=lambda rv: (_helpfulness(rv), _parse_dt(_safe_str(rv.get('created_at')))),
            reverse=True
        )
    else:  # recent
        all_reviews.sort(key=lambda rv: _parse_dt(_safe_str(rv.get('created_at'))), reverse=True)

    # pagination
    total_count = len(all_reviews)
    total_pages = max(1, (total_count + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, total_pages)
    start, end = (page - 1) * PAGE_SIZE, (page * PAGE_SIZE)
    reviews = all_reviews[start:end]
    cur_page = page

    # pin my review to top within the current page
    if current_user_id:
        mine = [rv for rv in reviews if int(rv.get('user_id', 0)) == int(current_user_id)]
        others = [rv for rv in reviews if int(rv.get('user_id', 0)) != int(current_user_id)]
        reviews = mine + others

    # pinned review (my review anywhere); only show if it matches stars filter (when set)
    pinned_review = None
    if current_user_id:
        try:
            mr = requests.get(
                f'{review_url}/api/reviews/mine/',
                params={'product_id': product_id},
                cookies=request.COOKIES, timeout=10
            ).json()
            pr = mr.get('review')
            if pr and (not stars or int(pr.get('rating',0)) == int(stars)):
                pinned_review = pr
        except Exception:
            pinned_review = None

    # de-dup pinned from this page
    if pinned_review:
        pr_id = int(pinned_review.get('review_id'))
        reviews = [rv for rv in reviews if int(rv.get('review_id')) != pr_id]
    
    can_review = bool(
        current_user_id and (_has_purchased(request, product_id) or pinned_review)
    )
    # pager URLs – preserve sort & stars
    base = reverse('reviews_page', args=[product_id])
    common = {}
    if sort and sort != 'recent':
        common['sort'] = sort
    if stars:
        common['stars'] = stars

    def page_url(n):
        q = common.copy()
        q['page'] = n
        return f"{base}?{urlencode(q)}"

    prev_url = page_url(cur_page - 1) if cur_page > 1 else None
    next_url = page_url(cur_page + 1) if cur_page < total_pages else None
    page_links = _build_page_links(cur_page, total_pages, page_url)
    return render(request, 'reviews.html', {
        'product': product,
        'reviews': reviews,
        'can_review': can_review,
        'pinned_review': pinned_review,
        'current_user_id': current_user_id,
        'cur_page': cur_page,
        'total_pages': total_pages,
        'prev_url': prev_url,
        'next_url': next_url,
        'stats': stats,
        'total_count': total_count,
        'sort': sort,
        'stars': stars,
        'rating_count': rating_count,
        'review_count': review_count,
        'page_links': page_links,
    })


@require_GET
def review_stats(request, product_id):
    try:
        rr = requests.get(f'{review_url}/api/reviews/stats/', params={'product_id': product_id}, timeout=8)
        data = rr.json() if rr.headers.get('content-type','').startswith('application/json') else {}
        return JsonResponse(data, status=rr.status_code, safe=True)
    except Exception:
        return JsonResponse({'error': 'review service unreachable'}, status=502)



@require_POST
def submit_review(request, product_id):
    if 'jwt' not in request.COOKIES:
        return JsonResponse({'ok': False, 'auth': False, 'error': 'Not authenticated'}, status=401)

    # Validate rating
    try:
        rating = int(request.POST.get('rating', 0))
        assert 1 <= rating <= 5
    except Exception:
        return JsonResponse({'ok': False, 'error': 'Rating must be 1..5'}, status=400)

    # Optional UX pre-check (server enforcement still happens in Review Service)
    if not _has_purchased(request, product_id):
        return JsonResponse({'ok': False, 'error': 'You must purchase this product before leaving a review.'}, status=403)

    data = {
        'product_id': product_id,
        'rating': rating,
        'title': request.POST.get('title', ''),
        'body': request.POST.get('body', ''),
    }

    # forward ALL images[] + legacy image
    files = []
    for f in request.FILES.getlist('images'):
        files.append(('images', (f.name, f.read(), f.content_type or 'application/octet-stream')))
    if 'image' in request.FILES:  # keep old single file support
        f = request.FILES['image']
        files.append(('image', (f.name, f.read(), f.content_type or 'application/octet-stream')))
    #videos[]
    for v in request.FILES.getlist('videos'):
        files.append(('videos', (v.name, v.read(), v.content_type or 'application/octet-stream')))

    try:
        r = requests.post(
            f'{review_url}/api/reviews/',
            data=data,
            files=files or None,
            cookies=request.COOKIES,
            timeout=15
        )
    except Exception:
        return JsonResponse({'ok': False, 'error': 'review service unreachable'}, status=502)

    ctype = r.headers.get('content-type', '')
    try:
        body = r.json() if 'application/json' in ctype else {'raw': r.text}
    except Exception:
        body = {'raw': r.text}

    return JsonResponse(body, status=r.status_code, safe=isinstance(body, dict))


@require_http_methods(["POST"])
def edit_review(request, review_id):
    if 'jwt' not in request.COOKIES:
        return JsonResponse({'ok': False, 'auth': False, 'error': 'Not authenticated'}, status=401)

    data = {}
    if 'rating' in request.POST:
        try:
            data['rating'] = int(request.POST['rating'])
            if not (1 <= data['rating'] <= 5):
                return JsonResponse({'ok': False, 'error': 'Rating must be 1..5'}, status=400)
        except Exception:
            return JsonResponse({'ok': False, 'error': 'Bad rating'}, status=400)
    if 'title' in request.POST:
        data['title'] = request.POST['title']
    if 'body' in request.POST:
        data['body'] = request.POST['body']

    # forward ALL images[] + legacy image
    files = []
    for f in request.FILES.getlist('images'):
        files.append(('images', (f.name, f.read(), f.content_type or 'application/octet-stream')))
    if 'image' in request.FILES:  # keep old single file support
        f = request.FILES['image']
        files.append(('image', (f.name, f.read(), f.content_type or 'application/octet-stream')))

    # Videos[]
    for v in request.FILES.getlist('videos'):
        files.append(('videos', (v.name, v.read(), v.content_type or 'application/octet-stream')))

    try:
        r = requests.patch(
            f'{review_url}/api/reviews/{review_id}/',
            data=data,
            files=files or None,
            cookies=request.COOKIES,
            timeout=15
        )
    except Exception:
        return JsonResponse({'ok': False, 'error': 'review service unreachable'}, status=502)

    ctype = r.headers.get('content-type', '')
    try:
        body = r.json() if 'application/json' in ctype else {'raw': r.text}
    except Exception:
        body = {'raw': r.text}

    return JsonResponse(body, status=r.status_code, safe=isinstance(body, dict))




@require_POST
def review_vote(request, review_id):
    print("\n[review_vote] HIT review_id:", review_id)
    if 'jwt' not in request.COOKIES:
        print("[review_vote] 401 no jwt")
        return JsonResponse({'ok': False, 'auth': False}, status=401)

    val = request.POST.get('value')
    print("[review_vote] value:", val)
    if val not in ('1', '-1'):
        print("[review_vote] 400 bad value")
        return JsonResponse({'ok': False, 'error': 'bad value'}, status=400)

    try:
        url = f'{review_url}/api/reviews/{review_id}/vote/'
        print("[review_vote] POST ->", url)
        r = requests.post(url, data={'value': val}, cookies=request.COOKIES, timeout=10)
        print("[review_vote] status:", r.status_code, "body:", r.text[:200])
        return JsonResponse(r.json(), status=r.status_code)
    except Exception as e:
        import traceback; traceback.print_exc()
        print("[review_vote] 502 review service unreachable")
        return JsonResponse({'ok': False, 'error': 'review service unreachable'}, status=502)


@require_POST
def delete_review(request, review_id):
    if 'jwt' not in request.COOKIES:
        return JsonResponse({'ok': False, 'auth': False}, status=401)
    try:
        # forward to Review Service DELETE /api/reviews/<id>/
        r = requests.delete(
            f'{review_url}/api/reviews/{review_id}/',
            cookies=request.COOKIES, timeout=10
        )
        # pass through JSON if present
        if r.headers.get('content-type','').startswith('application/json'):
            return JsonResponse(r.json(), status=r.status_code)
        return JsonResponse({'ok': r.ok}, status=r.status_code)
    except Exception:
        return JsonResponse({'ok': False, 'error': 'review service unreachable'}, status=502)
    


@require_GET
def review_gallery(request):
    rid = request.GET.get("review_id")
    if not rid:
        return HttpResponseNotFound("Missing review_id")

    try:
        start = int(request.GET.get("idx", 0))
    except Exception:
        start = 0

    # call review service
    try:
        r = requests.get(
            f"{review_url}/api/reviews/{rid}/",
            cookies=request.COOKIES,
            timeout=10
        )
    except requests.RequestException:
        return HttpResponseNotFound("Review service unreachable")

    if not r.ok or "application/json" not in (r.headers.get("content-type") or ""):
        return HttpResponseNotFound("Review not found")

    data = r.json()

    # collect images (multi first; fall back to legacy single)
    imgs = data.get("image_urls") or []
    if not imgs and data.get("image_url"):
        imgs = [data["image_url"]]
    vids = data.get("video_urls") or []

    # make any relative URLs absolute (e.g. "/media/…")
    base = review_url if review_url.endswith("/") else review_url + "/"
    def _abs(u: str) -> str:
        if not u:
            return u
        return u if u.startswith("http://") or u.startswith("https://") else urljoin(base, u.lstrip("/"))
    
    media = ([{"type":"image", "url": _abs((u or "").strip())} for u in imgs] +
         [{"type":"video", "url": _abs((u or "").strip())} for u in vids])

    context = {
        "media": media,
        "start_index": max(0, min(start, max(len(media) - 1, 0))),
        "title": data.get("title") or "",
        "body": data.get("body") or "",
        "rating": data.get("rating") or 0,
        "user_name": data.get("user_name") or "Anonymous",
        "is_verified": bool(data.get("is_verified_purchase")),
        "created_at": data.get("display_date") or "",
        "review_id": data.get("review_id") or rid,
        "like_count": data.get("like_count", 0),
        "dislike_count": data.get("dislike_count", 0),
    }
    # ensure text/html so your JS content-type check passes
    return render(request, "review_gallery.html", context, content_type="text/html; charset=utf-8")


