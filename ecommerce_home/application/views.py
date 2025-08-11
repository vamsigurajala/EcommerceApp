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
import jwt, datetime
from register.settings import user_url, product_url, cart_url, order_url, review_url
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt 
from django.views.decorators.http import require_POST, require_GET, require_http_methods 
from django.contrib import messages
from django.http import JsonResponse, HttpResponseNotFound
from urllib.parse import urljoin

def landing_page(request):
   return redirect("homepage")


class UserLoginAPIView(APIView):
    def get(self, request):
        return render(request, "userlogin.html")

    def post(self, request):
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, email=email, password=password)
        if user is None:
            return redirect('loginuser')

        if not user.check_password(password):
            return JsonResponse({'error': 'Incorrect password!'})

        # Generate JWT token
        payload = {
            'user_id': user.user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }
        token = jwt.encode(payload, 'secret', algorithm='HS256')
        
        # Create response
        response = redirect('paginatedproducts')
        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token,
            'user': UserSerializer(user).data,
        }
        print(response)

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
    return render(request, 'forgot_password.html')

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

def reviews_page(request, product_id):
    product = requests.get(f'{product_url}/api/singleproduct/{product_id}/').json()

    # who is logged in?
    current_user_id = _get_current_user_id(request)

    # can this user review? (verified purchase check)
    can_review = False
    if current_user_id:
        can_review = _has_purchased(request, product_id)   

    try:
        u = requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES).json()
        current_user_id = u.get('user_id')
    except Exception:
        pass

    # page param
    try:
        page = int(request.GET.get('page', '1'))
        if page < 1: page = 1
    except Exception:
        page = 1
# Fetch stats
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
        stats = {}
    # fetch this page of reviews
    r = requests.get(f'{review_url}/api/reviews/', params={'product_id': product_id, 'page': page},
                     cookies=request.COOKIES, timeout=10)
    data = r.json() if r.ok else {}
    reviews = data.get('results', []) if isinstance(data, dict) else []
    cur_page = int(data.get('page', page) or 1)
    total_pages = int(data.get('pages', 1) or 1)
    total_count = data.get('count', len(reviews))

    # Optional: move my review to top if it's in THIS page
    if current_user_id:
        mine = [rv for rv in reviews if int(rv.get('user_id', 0)) == int(current_user_id)]
        others = [rv for rv in reviews if not (int(rv.get('user_id', 0)) == int(current_user_id))]
        reviews = mine + others

    # NEW: fetch the user's review (regardless of page) so we can pin it at top
    pinned_review = None
    if current_user_id:
        try:
            mr = requests.get(
                f'{review_url}/api/reviews/mine/',
                params={'product_id': product_id},
                cookies=request.COOKIES, timeout=10
            ).json()
            pinned_review = mr.get('review')
        except Exception:
            pinned_review = None

# 🔧 DEDUPE: if pinned exists and is also in this page, remove it from the page list
    if pinned_review:
        pr_id = int(pinned_review.get('review_id'))
        reviews = [rv for rv in reviews if int(rv.get('review_id')) != pr_id]


    # build prev/next urls
    base = reverse('reviews_page', args=[product_id])
    prev_url = f"{base}?page={cur_page-1}" if cur_page > 1 else None
    next_url = f"{base}?page={cur_page+1}" if cur_page < total_pages else None

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

    # -------- key change: forward ALL images[] + legacy image --------
    files = []
    for f in request.FILES.getlist('images'):
        files.append(('images', (f.name, f.read(), f.content_type or 'application/octet-stream')))
    if 'image' in request.FILES:  # keep old single file support
        f = request.FILES['image']
        files.append(('image', (f.name, f.read(), f.content_type or 'application/octet-stream')))

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

    # -------- key change: forward ALL images[] + legacy image --------
    files = []
    for f in request.FILES.getlist('images'):
        files.append(('images', (f.name, f.read(), f.content_type or 'application/octet-stream')))
    if 'image' in request.FILES:  # keep old single file support
        f = request.FILES['image']
        files.append(('image', (f.name, f.read(), f.content_type or 'application/octet-stream')))

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

    # make any relative URLs absolute (e.g. "/media/…")
    base = review_url if review_url.endswith("/") else review_url + "/"
    def _abs(u: str) -> str:
        if not u:
            return u
        return u if u.startswith("http://") or u.startswith("https://") else urljoin(base, u.lstrip("/"))
    imgs = [_abs((u or "").strip()) for u in imgs]

    context = {
        "images": imgs,
        "start_index": max(0, min(start, max(len(imgs) - 1, 0))),
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