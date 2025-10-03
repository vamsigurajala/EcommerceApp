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
from datetime import datetime, timedelta  
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


def landing_page(request):
   return redirect("homepage")

#LOGIN AND SIGNUP PAGE CODE

class UserLoginAPIView(APIView):
    def get(self, request):
        # Allow showing errors via context too (optional)
        return render(request, "userlogin.html")

    def post(self, request):
        email = (request.POST.get('email') or '').strip()
        password = request.POST.get('password') or ''

        user = authenticate(request, email=email, password=password)
        if user is None:
            # Bad credentials → show inline error and preserve email
            return render(
                request,
                "userlogin.html",
                {
                    "message_type": "error",
                    "message": "Invalid email or password.",
                    "email": email,
                },
                status=401,
            )

        # (Optional) block inactive users
        if not user.is_active:
            return render(
                request,
                "userlogin.html",
                {
                    "message_type": "error",
                    "message": "Your account is inactive. Please contact support.",
                    "email": email,
                },
                status=403,
            )

        # Success: issue JWT and continue
        payload = {
            'user_id': user.user_id,
            'exp': datetime.utcnow() + timedelta(minutes=60),
            'iat': datetime.utcnow(),
        }
        token = jwt.encode(payload, 'secret', algorithm='HS256')

        response = redirect('paginatedproducts')
        response.set_cookie(key='jwt', value=token, httponly=True)
        return response


class UserDetailsView(APIView):
    permission_classes = []  

    JWT_SECRET = 'secret'
    JWT_ALGORITHM = 'HS256'

    def get_user(self, token):
        if not token:
            raise AuthenticationFailed('Unauthenticated')
        payload = jwt.decode(token, self.JWT_SECRET, algorithms=[self.JWT_ALGORITHM])
        return User.objects.get(pk=payload['user_id'])

    def get(self, request):
        user = self.get_user(request.COOKIES.get('jwt'))
        data = UserSerializer(user).data
        # Don’t leak password hash (write_only anyway), just return the fields we care about
        return Response({
            'user_id': data['user_id'],
            'username': data['username'],
            'email': data['email'],
            'phone': data.get('phone')
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

        # *** IMPORTANT: auto-login by issuing the JWT like your login view ***
        payload = {
            'user_id': user.user_id,
            'exp': datetime.utcnow() + timedelta(minutes=60),
            'iat': datetime.utcnow(),
        }
        token = jwt.encode(payload, 'secret', algorithm='HS256')

        resp = redirect('addingaddress')   # or whatever name maps to address.html
        resp.set_cookie(key='jwt', value=token, httponly=True)
        return resp



class LogoutView(APIView):
    def post(self, request):
        response = redirect('home.html')
        response.delete_cookie('jwt')
        response.data={
            'message':'Successlly logged out'
        }
        return Response(response.data, status=status.HTTP_200_OK)


class AddressView(APIView):
    JWT_SECRET = 'secret'
    JWT_ALGORITHM = 'HS256'

    def get_user_id(self, token):
        if not token:
            raise AuthenticationFailed('User not authenticated!')
        try:
            payload = jwt.decode(token, self.JWT_SECRET, algorithms=[self.JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired!')
        return payload['user_id']

    def get(self, request):
        token = request.COOKIES.get('jwt')
        user_id = self.get_user_id(token)
        addresses = Address.objects.filter(user_id=user_id).order_by('-updated_at', '-created_at')
        serializer = AddressSerializer(addresses, many=True)
        return Response({'addresses': serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        token = request.COOKIES.get('jwt')
        user_id = self.get_user_id(token)
        #serializer = AddressSerializer(data=request.data)
        serializer = AddressSerializer(data={**request.data, 'user': self.get_user_id(request.COOKIES.get('jwt'))})
        if serializer.is_valid():
            # set FK via *_id is fine
            serializer.save(user_id=user_id)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        """
        Update an address that belongs to the logged-in user.
        Pass ?address_id=<id> in the query string.
        """
        token = request.COOKIES.get('jwt')
        user_id = self.get_user_id(token)
        addr_id = request.query_params.get('address_id')

        if not addr_id:
            return Response({'detail': 'address_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            addr = Address.objects.get(pk=addr_id)
        except Address.DoesNotExist:
            return Response({'detail': 'Address not found'}, status=status.HTTP_404_NOT_FOUND)

        if addr.user_id != user_id:
            raise PermissionDenied('Not your address')

        serializer = AddressSerializer(addr, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()  # user_id stays same
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        token = request.COOKIES.get('jwt')
        user_id = self.get_user_id(token)
        addr_id = request.query_params.get('address_id')

        if not addr_id:
            return Response({'detail': 'address_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            addr = Address.objects.get(pk=addr_id)
        except Address.DoesNotExist:
            return Response({'detail': 'Address not found'}, status=status.HTTP_404_NOT_FOUND)

        if addr.user_id != user_id:
            raise PermissionDenied('Not your address')

        addr.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)



def _jwt_user_id(request):
    # same secret/alg as elsewhere
    token = request.COOKIES.get('jwt')
    if not token:
        return None
    try:
        payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        return payload.get('user_id')
    except jwt.ExpiredSignatureError:
        return None

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

    context = {
        'products': products,
        'next_url': next_url,
        'next_page': int(page)+1,
        'prev_url': prev_url,
        'prev_page': int(page)-1,
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

    #Get cart count
    cart_count = 0
    try:
        cart_resp = requests.get(f'{cart_url}/api/cartitems/', cookies=request.COOKIES).json()
        if isinstance(cart_resp, list):
            cart_count = sum(int(item.get('quantity', 0)) for item in cart_resp)
    except Exception:
        cart_count = 0

    context = {
        'products': products,
        'next_url': next_url,
        'next_page': int(page) + 1,
        'prev_url': prev_url,
        'prev_page': int(page) - 1,
        'user': user,
        'cart_count': cart_count,   
    }
    return render(request, 'products.html', context)




class GetUserIdAPIView(views.APIView): #Get the UserId
    def get(self, request, *args, **kwargs):
        user_id = kwargs['user_id']
        user = User.objects.get(user_id=user_id)
        return Response( UserSerializer(user).data)


# CART SERVICE CODE
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

    # compute updated count
    cart_count = 0
    try:
        cart_resp = requests.get(f'{cart_url}/api/cartitems/', cookies=request.COOKIES).json()
        if isinstance(cart_resp, list):
            cart_count = sum(int(item.get('quantity', 0)) for item in cart_resp)
    except Exception:
        pass

    return JsonResponse({'ok': True, 'cart_count': cart_count})


def cart(request):
    # Initialize cartitems to None
    cartitems=None

    # Check if user is authenticated
    if requests and request.COOKIES and  'jwt' in request.COOKIES:
        response  = requests.get(f'{user_url}/api/userview/', cookies = request.COOKIES).json()
        user_id=response['user_id']
    else:
        return redirect(f'{user_url}/api/login/')
    
    # Retrieve the cart items from the cart service
    cart_response = requests.get(f'{cart_url}/api/cartitems/', cookies=request.COOKIES)
    
    #Check if cart is empty
    if 'message' in cart_response.json():
        message= cart_response.json()['message']
        return render(request, "cart.html", {'user_id':user_id, 'cartitems':cartitems, 'message': message})
    
    # If cart is not empty, process the cart items
    cartitems=cart_response.json()
    cart_total=0
    #cart_count = 0 
    for item in cartitems:
        # Retrieve product details from the product service
        product_id = item["product_id"]
        product=requests.get(f'{product_url}/api/productview/{product_id}/', data= item).json()
        product['image']=product['image'].replace('http://152.14.0.14','http://127.0.0.1')
        item['product'] = product
        # Calculate total price for each item
        item['total_price'] = item['quantity'] * float(product['price'])
        cart_total+=item['total_price']
        #cart_count += int(item['quantity']) 
    return render(request, 'cart.html',{'user_id':user_id, 'cartitems':cartitems, 'cart_total':cart_total, 'message':None})    
        

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

def clear_cart(request):

    if 'jwt' in request.COOKIES.keys():
        resposne = requests.get(f'{user_url}/api/userview/', cookies = request.COOKIES).json()['user_id']
    else:
        return redirect(f'{user_url}/api/login/')
    
    product_id =  request.GET['product_id']
    reposne = requests.post(f'{cart_url}/api/clearcart/',data=request.GET, cookies=request.COOKIES).json()
    return redirect('/api/cart/')


def get_user_address(request):
    user_id=requests.get(f'{user_url}/api/userview/',cookies=request.COOKIES).json()['user_id']

    # Get the user's address from the Address model
    address=Address.objects.filter(user_id=user_id).first()
    context={'address':address}
    return render(request, 'address.html', context)


"""
def checkout(request):
    if request.method=='GET':
        if 'jwt' in request.COOKIES.keys():

            user_id = requests.get(f'{user_url}/api/userview/', cookies = request.COOKIES).json()['user_id']
        else:
            return redirect(f'{user_url}/api/login/')
        address_response = requests.get(f'{user_url}/api/getaddress/', cookies= request.COOKIES).json()
        address = address_response['addresses'][0] 

        # full_address_response = requests.get(f'http://127.0.0.1:8000/api/getaddress/{address["address_id"]}/', cookies=request.COOKIES).json
        # full_address = full_address_response['address']
        # print(full_address_response)
        
        cart_items_response = requests.get(f'{cart_url}/api/cartitems/', cookies=request.COOKIES).json()
        cart_total=0
        for item in cart_items_response:
            product_id = item["product_id"]
            product=requests.get(f'{product_url}/api/productview/{product_id}/', data= item).json()
            product['image']=product['image'].replace('http://152.14.0.14','http://127.0.0.1')
            item['product'] = product
            item['total_price'] = item['quantity'] * float(product['price'])
            cart_total+=item['total_price'] 
        cart_items = [
        {**cart_item, **requests.get(f'{product_url}/api/singleproduct/{cart_item["product_id"]}/', cookies=request.COOKIES).json()}
        for cart_item in cart_items_response
        ]
        return render(request, "checkout.html" , {'orders_data': cart_items, 'addresses': address_response['addresses'], 'cart_total':cart_total})#, 'full_address' : full_address_response['addresses']})
    elif request.method=="POST":
        return start_payment_from_checkout(request)

    ''' if 'jwt' in request.COOKIES.keys():

            user_id = requests.get(f'{user_url}/api/userview/', cookies = request.COOKIES).json()['user_id']
        else:

            return redirect(f'{user_url}/api/login/')
        
        address_response = requests.get(f'{user_url}/api/getaddress/', cookies= request.COOKIES).json()
        address = address_response['addresses'][0]  

        # full_address_response = requests.get(f'http://127.0.0.1:8000/api/getaddress/{address["address_id"]}/', cookies=request.COOKIES).json
        # full_address = full_address_response['address']
        # print(full_address_response)

        # Get user's cart items and calculate the total price
        cart_items_response = requests.get(f'{cart_url}/api/cartitems/', cookies=request.COOKIES).json()
        cart_total=0
        for item in cart_items_response:
            product_id = item["product_id"]
            product=requests.get(f'{product_url}/api/productview/{product_id}/', data= item).json()
            item['product'] = product
            item['total_price'] = item['quantity'] * float(product['price'])
            cart_total+=item['total_price']

        # Get detailed product information for each item in the cart
        cart_items = [
            {**cart_item, **requests.get(f'{product_url}/api/singleproduct/{cart_item["product_id"]}/', cookies=request.COOKIES).json()}
            for cart_item in cart_items_response
        ]
        #print(cart_items)
        orders_data = {
            'user_id': user_id,
            'address': address,
            'items': cart_items,
        }
        print(orders_data)
        # Place the order using the orders_data dictionary and save the response
        order_response = requests.post(f'{order_url}/api/placeorder/', data={"order":json.dumps( orders_data)}, cookies=request.COOKIES)
        reposne = requests.post(f'{cart_url}/api/clearcart/',data=request.GET, cookies=request.COOKIES).json()

        orders_data = json.dumps(orders_data)
        messages.success(request, "Order placed successfully!")
        return redirect('/api/vieworders/?placed=1')'''
    
from django.contrib.messages import get_messages

def _clear_messages(request):
    # iterate once to consume anything pending
    for _ in get_messages(request):
        pass

import uuid as py_uuid

def start_payment_from_checkout(request):
    if 'jwt' not in request.COOKIES:
        return redirect(f'{user_url}/api/login/')

    # address
    address_response = requests.get(f'{user_url}/api/getaddress/', cookies=request.COOKIES).json()
    addresses = address_response.get('addresses') or []
    if not addresses:
        messages.error(request, "No address on file. Please add an address.")
        return redirect('/api/getaddress/')
    address = addresses[0]

    # cart
    cart_items_response = requests.get(f'{cart_url}/api/cartitems/', cookies=request.COOKIES).json()
    cart_total = 0.0
    for item in cart_items_response:
        product_id = item["product_id"]
        product = requests.get(f'{product_url}/api/productview/{product_id}/', data=item).json()
        item['product'] = product
        item['total_price'] = item['quantity'] * float(product['price'])
        cart_total += item['total_price']

    cart_items = [
        {**cart_item, **requests.get(f'{product_url}/api/singleproduct/{cart_item["product_id"]}/', cookies=request.COOKIES).json()}
        for cart_item in cart_items_response
    ]

    user_id = _get_current_user_id(request)
    orders_data = {
        'user_id': user_id,
        'address': address,
        'items': cart_items,
    }

    total_amount = round(cart_total, 2)
    idemp = str(py_uuid.uuid4())

    # 🔹 DEBUG STARTS HERE
    intent_url = f"{payment_url.rstrip('/')}/payments/intents/"
    payload = {
        "order_id": 0,
        "user_id": user_id,
        "amount": total_amount,
        "currency": "INR",
        "provider": "razorpay",
        "idempotency_key": idemp,
        "metadata": {
            "source": "cart_checkout",
            "orders_data": orders_data
        }
    }
    print("DEBUG >> POSTing to:", intent_url)
    print("DEBUG >> Payload:", payload)
    # 🔹 DEBUG ENDS HERE

    try:
        r = requests.post(intent_url, json=payload, timeout=10)

        # 🔹 EXTRA DEBUG
        print("DEBUG >> Response status:", r.status_code)
        print("DEBUG >> Response body:", r.text)

        if not r.ok:
            messages.error(request, "Could not start payment. Please try again.")
            return redirect('/api/paginate/')
        payment_payload = r.json()
    except Exception as e:
        print("DEBUG >> Exception during payment POST:", str(e))
        messages.error(request, "Payment service unreachable.")
        return redirect('/api/paginate/')

    request.session['__pending_order__'] = orders_data
    request.session['__pending_payment__'] = payment_payload

    return render(request, "payment.html", {
        "amount": total_amount,
        "currency": "INR",
        "payment": payment_payload,
        "order": orders_data,
    })

@csrf_exempt
def payment_success(request):
    #Called from payment.html after a successful (or mock) payment.
    orders_data = request.session.get('__pending_order__')
    payment = request.session.get('__pending_payment__')
    if not orders_data or not payment:
        _clear_messages(request)
        messages.error(request, "No pending payment found.")
        return redirect('/api/paginate/')

    try:
        order_resp = requests.post(
            f'{order_url}/api/placeorder/',
            data={"order": json.dumps(orders_data)},
            cookies=request.COOKIES, timeout=12
        )
        if not order_resp.ok:
            _clear_messages(request)
            messages.error(request, "Order creation failed after payment. Contact support.")
            return redirect('/api/paginate/')

        # clear the cart best-effort
        try:
            requests.post(f'{cart_url}/api/clearcart/', data={}, cookies=request.COOKIES, timeout=8)
        except Exception:
            pass

        # cleanup
        request.session.pop('__pending_order__', None)
        request.session.pop('__pending_payment__', None)

        _clear_messages(request)
        messages.success(request, "Payment successful! Order placed.")
        return redirect('/api/vieworders/?placed=1')
    except Exception:
        _clear_messages(request)
        messages.error(request, "Unexpected error while finalizing order.")
        return redirect('/api/paginate/')


def payment_failure(request):
    # make sure only ONE toast shows after this redirect
    _clear_messages(request)
    messages.error(request, "Payment cancelled. No money was taken.")
    # choose where you want to land users after cancel:
    return redirect('/api/paginate/') 
"""

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


@require_POST
def start_payment_from_checkout(request):
    """
    Start payment using the *exact* snapshot saved by checkout().
    Snapshot is stored in request.session['checkout_snapshot'].
    """
    if 'jwt' not in request.COOKIES:
        return redirect(f'{user_url}/api/login/')

    # 1) Selected address
    sel_addr_id = request.POST.get('address_id')
    try:
        address_response = requests.get(
            f'{user_url}/api/getaddress/',
            cookies=request.COOKIES,
            timeout=8
        ).json()
        addresses = address_response.get('addresses', []) or []
    except Exception:
        addresses = []

    if not addresses:
        messages.error(request, "No address on file. Please add an address.")
        return redirect('/api/getaddress/')

    if sel_addr_id:
        address = next(
            (a for a in addresses if str(a.get('address_id')) == str(sel_addr_id)),
            addresses[0]
        )
    else:
        address = addresses[0]

    # 2) Pull the frozen snapshot created by checkout()
    snap = request.session.get('checkout_snapshot')
    if not snap:
        messages.error(request, "Session expired. Please open checkout again.")
        return redirect('/api/checkout/')

    # snapshot → plain floats only (no Decimal!)
    items         = snap.get("items", [])
    item_count    = int(snap.get("item_count", 0))
    cart_total    = float(snap.get("cart_total", 0.0))
    shipping_fee  = float(snap.get("shipping_fee", 0.0))
    platform_fee  = float(snap.get("platform_fee", 0.0))
    total_payable = float(snap.get("total_payable", 0.0))

    user_id = _get_current_user_id(request)

    # 3) Build the order payload to keep across the flow
    orders_data = {
        "user_id": user_id,
        "address": address,
        "items": items,
        "summary": {
            "item_count": item_count,
            "cart_total": cart_total,
            "shipping_fee": shipping_fee,
            "platform_fee": platform_fee,
            "total_payable": total_payable,
        }
    }

    # Amount to charge = what the user saw
    total_amount = round(total_payable, 2)
    idemp = str(uuid.uuid4())

    # 4) Create a payment intent with your gateway service
    intent_url = f"{payment_url.rstrip('/')}/payments/intents/"
    payload = {
        "order_id": 0,
        "user_id": user_id,
        "amount": total_amount,         # float → JSON-safe
        "currency": "INR",
        "provider": "razorpay",
        "idempotency_key": idemp,
        "metadata": {
            "source": "cart_checkout",
            "orders_data": orders_data   # dict with only JSON-safe types
        }
    }
    try:
        r = requests.post(intent_url, json=payload, timeout=10)
        if not r.ok:
            messages.error(request, "Could not start payment. Please try again.")
            return redirect('/api/paginate/')
        payment_payload = r.json()
    except Exception:
        messages.error(request, "Payment service unreachable.")
        return redirect('/api/paginate/')

    # 5) Persist for success/failure handlers
    request.session['__pending_order__'] = orders_data
    request.session['__pending_payment__'] = payment_payload
    request.session.modified = True

    # 6) Render the payment page with the exact snapshot amounts
    return render(request, "payment.html", {
        "amount": total_amount,
        "currency": "INR",
        "payment": payment_payload,
        "order": orders_data,

        # right price card + buttons
        "item_count": item_count,
        "cart_total": cart_total,
        "shipping_fee": shipping_fee,
        "platform_fee": platform_fee,
        "total_payable": total_payable,
    })


@csrf_exempt
def payment_success(request):
    """
    Called by your payment return/handler when the payment is successful.
    Uses the pending order saved in session.
    """
    orders_data = request.session.get('__pending_order__')
    # --- ensure final total (cart + shipping + platform) is carried into the order ---
    summary = (orders_data or {}).get("summary", {}) if orders_data else {}
    final_total = float(summary.get("total_payable") or (
        float(summary.get("cart_total") or 0) +
        float(summary.get("shipping_fee") or 0) +
        float(summary.get("platform_fee") or 0)
    ))

    # put it in both a summary field (for safety) and a top-level legacy key
    if orders_data is not None:
        summary["final_total"] = final_total
        orders_data["summary"] = summary
        orders_data["total_amount"] = final_total

    if not orders_data:
        _clear_messages(request)
        messages.error(request, "No pending payment found.")
        return redirect('/api/paginate/')

    try:
        # Place order in your Orders service
        order_resp = requests.post(
            f'{order_url}/api/placeorder/',
            data={"order": json.dumps(orders_data)},
            cookies=request.COOKIES,
            timeout=12
        )
        if not order_resp.ok:
            _clear_messages(request)
            messages.error(request, "Order creation failed after payment. Contact support.")
            return redirect('/api/paginate/')

        # Best effort clear cart
        try:
            requests.post(f'{cart_url}/api/clearcart/', data={}, cookies=request.COOKIES, timeout=8)
        except Exception:
            pass

        # Clean session state
        request.session.pop('__pending_order__', None)
        request.session.pop('__pending_payment__', None)
        request.session.pop('checkout_snapshot', None)
        request.session.modified = True

        _clear_messages(request)
        messages.success(request, "Payment successful! Order placed.")
        return redirect('/api/vieworders/?placed=1')
    except Exception:
        _clear_messages(request)
        messages.error(request, "Unexpected error while finalizing order.")
        return redirect('/api/paginate/')



def payment_failure(request):
    _clear_messages(request)
    messages.error(request, "Payment cancelled. No money was taken.")
    return redirect('/api/paginate/')


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

def vieworders(request):
    r = requests.get(f'{order_url}/api/placeorder/', cookies=request.COOKIES, timeout=10)
    if not r.ok:
        return render(request, "vieworder.html", {"order_data": []})

    order_data = r.json()
    if isinstance(order_data, str):
        try:
            order_data = json.loads(order_data)
        except json.JSONDecodeError:
            order_data = {}

    for order in order_data.get('orderlist', []):
        items = order.get('order_items', []) or []

        # 1) cart_total from items (prefer item's own total_price; else qty * price)
        cart_total = 0.0
        for it in items:
            try:
                line_total = it.get('total_price')
                if line_total is None:
                    qty = float(it.get('quantity') or 1)
                    # try multiple spots for unit price
                    unit = it.get('price')
                    if unit is None:
                        unit = (it.get('product') or {}).get('price')
                    unit = float(unit or 0)
                    line_total = qty * unit
                cart_total += float(line_total or 0)
            except (TypeError, ValueError):
                pass

        # 2) fees (same rules you used in checkout)
        shipping_fee = 0.0 if cart_total == 0 else (0.0 if cart_total >= 1500 else 100.0)
        platform_fee = 0.0 if cart_total == 0 else float(PLATFORM_FEE_RS)  # import/read same const

        # 3) prefer server-provided summary, else compute our own final total
        summary = order.get('summary', {}) or {}
        # if backend didn’t store final_total, compute it
        final_total = summary.get('final_total')
        if final_total is None:
            final_total = summary.get('total_payable')

        if final_total is None:
            # Backend lost the fees — reconstruct deterministically
            final_total = cart_total + shipping_fee + platform_fee

        try:
            final_total = float(final_total)
        except (TypeError, ValueError):
            final_total = cart_total + shipping_fee + platform_fee

        # 4) keep a consistent shape for the template
        summary.update({
            "item_count": len(items),
            "cart_total": float(cart_total),
            "shipping_fee": float(shipping_fee),
            "platform_fee": float(platform_fee),
            "total_payable": float(cart_total + shipping_fee + platform_fee),
            "final_total": float(final_total),
        })
        order['summary'] = summary
        order['total_amount'] = float(final_total)  # canonical total for the UI

        # 5) (your existing enrichment)
        for item in items:
            pid = item.get("product_id")
            if pid is None:
                continue
            try:
                product_data = requests.get(
                    f'{product_url}/api/productview/{pid}/',
                    cookies=request.COOKIES, timeout=8
                ).json()
                item['product_name'] = product_data.get('product_name')
                img = product_data.get('image') or ''
                item['image'] = img.replace('http://152.14.0.14','http://127.0.0.1')
            except Exception:
                item.setdefault('product_name', 'Unknown product')
                item.setdefault('image', '')
            item['my_review_id'] = _get_my_review_id(pid, request)

    return render(request, "vieworder.html", {"order_data": order_data.get('orderlist', [])})


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
        'pinned_review': pinned_review,
        'current_user_id': current_user_id,
        'cur_page': cur_page,
        'total_pages': total_pages,
        'prev_url': prev_url,
        'next_url': next_url,
        'stats': stats,
        'total_count': total_count,
        'can_review': can_review,
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


def _get_current_user_id(request):
    try:
        data = requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES, timeout=8).json()
        return data.get('user_id')
    except Exception:
        return None

def _has_purchased(request, product_id) -> bool:
    """
    Calls Order Service internal endpoint to check if the logged-in user bought the product.
    """
    user_id = _get_current_user_id(request)
    if not user_id:
        return False
    try:
        r = requests.get(
            f'{order_url}/api/internal/has-purchased/',
            params={'user_id': str(user_id), 'product_id': str(product_id)},
            timeout=6
        )
        if r.ok:
            data = r.json()
            return bool(data.get('has_purchased'))
        return False
    except Exception:
        return False
    

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


