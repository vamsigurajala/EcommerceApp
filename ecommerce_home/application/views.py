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
from rest_framework import views, status, generics
import json
import jwt
from datetime import datetime, timedelta  
from register.settings import user_url, product_url, cart_url, order_url, review_url
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


def landing_page(request):
   return redirect("homepage")


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
    def get(self, request):

        # Retrieve JWT token from cookies
        token=request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('User not authenticated!')
        
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired!')
        
        # Get user from database using user_id from JWT token
        user = User.objects.filter(user_id=payload['user_id']).first()
        serializer = UserSerializer(user)
        user_id=serializer.data.get('user_id')
        return Response(serializer.data)
    

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


def usersignup(request):
    if request.method=="GET":

        return render(request, "usersignup.html")
    elif request.method=="POST":
            
            print(request.POST['name'])
            if request.POST['user_role']=='buyer':

                user=User(username= request.POST['name'], 
                        email= request.POST['email'], 
                        age=request.POST['age'],
                        gender=request.POST['gender'],
                        user_role_id = 1)
                
                if(request.POST['password']!="") and (request.POST['confirm_password']!="") and (request.POST['password'] == request.POST['confirm_password']):

                    user.set_password(request.POST['password'])
                    user.save()
            else:
                user=User(username= request.POST['name'], 
                        email= request.POST['email'], 
                        age=request.POST['age'],
                        gender=request.POST['gender'],
                        user_role_id = 2)
                
                if(request.POST['password']!="") and (request.POST['confirm_password']!="") and (request.POST['password'] == request.POST['confirm_password']):

                    user.set_password(request.POST['password'])
                    user.save()
            return render(request, "address.html")
        


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
        addresses = Address.objects.filter(user=user_id)
        if addresses:

            serializer = AddressSerializer(addresses, many=True)
            return Response({'addresses': serializer.data})
        else:
            return Response({'message': 'User has no address'})

    def post(self, request):
        token = request.COOKIES.get('jwt')
        user_id = self.get_user_id(token)
        address_serializer = AddressSerializer(data=request.data)
        if address_serializer.is_valid():

            address_serializer.save(user_id=user_id)
            return Response(address_serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(address_serializer.errors, status=status.HTTP_400_BAD_REQUEST)



def useraddress(request):
    # Get the user id from the response of the 'UserDetailsView' API
    user_id = requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES).json()['user_id']
    
    if request.method == "POST":
        # Create a new Address object with the provided data
        address_object = Address(user_id=user_id,
                                 door_no=request.POST['door_no'],
                                 street=request.POST['street'],
                                 area=request.POST['area'],
                                 city=request.POST['city'],
                                 state=request.POST['state'],
                                 pincode=request.POST['pincode'],
                                 country=request.POST['country'])
        address_object.save() # Save the object to the database 
        return redirect('/api/login/')
    
    else:
        # Render the 'address.html' template for GET requests
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
        


def products(request):
    response = requests.get(f'{product_url}/api/products/')
   # print(type(json.loads(response.content)))
    products=json.loads(response.content)
    return render(request, 'allproducts.html', {'products': products})




def product_info(request):
    response = requests.get(f'{product_url}/api/allproducts/')
    products=json.loads(response.content)
    return render(request, 'products.html',{ "products" :products})


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
        if 'jwt' in request.COOKIES.keys():

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
        return redirect('/api/vieworders/?placed=1')


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
    # If the service sent a JSON *string*, decode it
    if isinstance(order_data, str):
        try:
            order_data = json.loads(order_data)
        except json.JSONDecodeError:
            order_data = {}

    for order in order_data.get('orderlist', []):     # for each item, attach product details and "my_review_id"
        for item in order.get('order_items', []):
            product_id = item.get("product_id")
            if product_id is None:
                continue
            try:             # product name + image (as you already did)
                product_data = requests.get(
                    f'{product_url}/api/productview/{product_id}/',
                    cookies=request.COOKIES, timeout=8
                ).json()
                item['product_name'] = product_data.get('product_name')
                img = product_data.get('image') or ''
                item['image'] = img.replace('http://152.14.0.14','http://127.0.0.1')
            except Exception:
                item.setdefault('product_name', 'Unknown product')
                item.setdefault('image', '')
            item['my_review_id'] = _get_my_review_id(product_id, request)
    return render(request, "vieworder.html", {"order_data": order_data.get('orderlist', [])})



from django.urls import reverse


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


