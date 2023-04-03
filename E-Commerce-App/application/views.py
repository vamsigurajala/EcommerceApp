from django.http import HttpResponse, request,HttpResponseBadRequest
from django.shortcuts import redirect, render
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from .serializers import UserSerializer, AddressSerializer
from .models import User, Address
from django.conf import settings 
from django.http import JsonResponse
from django.db import IntegrityError
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
import requests
from rest_framework.decorators import api_view
from rest_framework import views, status, generics
import json
import jwt, datetime
from register.settings import user_url, product_url, cart_url, order_url, review_url




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
        return Response({'user_id':user_id})
    


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
def paginate(request, page = None,search=None):
    user_id = request.session.get('user_id')
    page_number = request.GET.get('page',1)  # Default to page 1 if no page number is specified

    if 'search' in request.GET.keys():
        search = request.GET['search']

    if search:
        url = f'{product_url}/api/productsearch/?search={search}&page={page_number}'

    else:
        url = f'{product_url}/api/getproducts/?page={page_number}'
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
    return render(request, 'products.html', context)




class GetUserIdAPIView(views.APIView): #Get the UserId
    def get(self, request, *args, **kwargs):
        user_id = kwargs['user_id']
        user = User.objects.get(user_id=user_id)
        return Response( UserSerializer(user).data)




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
    for item in cartitems:
        # Retrieve product details from the product service
        product_id = item["product_id"]
        product=requests.get(f'{product_url}/api/productview/{product_id}/', data= item).json()
        product['image']=product['image'].replace('http://152.14.0.14','http://127.0.0.1')
        item['product'] = product
        # Calculate total price for each item
        item['total_price'] = item['quantity'] * float(product['price'])
        cart_total+=item['total_price']
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

        # context = {
        #     'addresses': address_response['addresses'],
        #     'orders_data': cart_items,
        #     'cart_total':cart_total,
        # }
        return redirect('/api/vieworders/')




def vieworders(request):
    order_data = requests.get(f'{order_url}/api/placeorder/', cookies= request.COOKIES).json()
    # print(type(json.loads(order_data)))
    order_data=json.loads(order_data)
    # print(order_data)

    for order in order_data['orderlist']:
        for item in order['order_items']:
            product_data = requests.get(f'{product_url}/api/productview/{item["product_id"]}/', cookies=request.COOKIES).json()
            item['product_name'] = product_data['product_name']
            item['image'] = product_data['image']
            item['image'] = item['image'].replace('http://152.14.0.14','http://127.0.0.1')
            # print(item['product_name'] )

            # print(item['image'] )
       
    return render(request, "vieworder.html", {"order_data": order_data['orderlist']})



def write_review(request, product_id):
    if request.method == 'GET':
        if 'jwt' in request.COOKIES.keys():

            user_id = requests.get(f'{user_url}/api/userview/', cookies = request.COOKIES).json()['user_id']
        else:
            return redirect(f'{user_url}/api/login/')
        for item in products:
            product_id=item["product_id"]
            product_data = requests.get(f'{product_url}/api/singleproduct/{product_id}/', cookies=request.COOKIES).json()

        return render(request, 'review.html', {'product': product_data})

    elif request.method == 'POST':
        user_id = requests.get(f'{user_url}/api/userview/', cookies = request.COOKIES).json()['user_id']
        product_data = requests.get(f'{product_url}/api/singleproduct/{product_id}/', cookies=request.COOKIES).json()

        review_data = {
            'user_id': request.user.id,
            'product_id': product_id,
            'rating': request.POST.get('rating'),
            'comment': request.POST.get('comment'),
            'posted_on':request.POST.get('posted_on'),
        }
        response = requests.post(f'{review_url}/review/', json=review_data, cookies=request.COOKIES)
        return redirect('/api/seereviews/')


def product_reviews(request, product_id):
    review_data = requests.get(f'{review_url}/review/', cookies=request.COOKIES).json()
    reviews = review_data['reviews']
    product_data = requests.get(f'{product_url}/api/productview/{product_id}/', cookies=request.COOKIES).json()
    return render(request, 'product_reviews.html', {'reviews': reviews, 'product': product_data})

