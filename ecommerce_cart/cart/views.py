from django.shortcuts import render
from django.http import HttpResponse, request
from rest_framework import views, status
from .models import Cart, CartItems
from rest_framework.response import Response
from .serializers import CartSerializer, CartItemsSerializer
import json
import requests
from cartproject.settings import user_url, product_url, cart_url, order_url, review_url


# Create your views here.
def cartfun(request):
    return HttpResponse("This is ntg but cart")



# CartAPIView handles GET and POST requests for a user's cart.
class CartAPIView(views.APIView):
    def get(self, request):

        response = requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES).json()['user_id']
        if Cart.objects.filter(user_id = response).first() is None:

            # If the user doesn't have a cart, create a new cart object and save it using the CartSerializer.
            serializer=CartSerializer(data={'user_id':response})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            # Otherwise, retrieve the existing cart object and serialize it.
        else:

            identifier = Cart.objects.filter(user_id=response).first()
            serializer=CartSerializer(identifier)
        return Response(serializer.data)
        

    def post(self, request):        # POST method adds a new item to the user's cart.
        data =  request.data
        response =  requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES).json()
        user_id = response["user_id"]
        cart,_ =Cart.objects.get_or_create(user_id = user_id)
        product_id = int(data.get("product_id"))        
        
        # Create a new CartItems object and save it to the database.
        cartitems = CartItems(cart_id= cart, product_id=product_id)
        print(cartitems)
        cartitems.save()
        return Response({
            'message' : 'succesfully added'
        })



    

class CartItemsAPIView(views.APIView):
    def get(self, request):
        
        # Retrieve user_id and cart_id from API responses
        response = requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES).json()['user_id']
        cart_response =requests.get(f'{cart_url}/api/cartview/', cookies=request.COOKIES).json()
        cart_id=cart_response['cart_id']

        # Retrieve cart items for the user's cart, and serialize them if they exist
        cart_items=CartItems.objects.filter(cart_id = cart_id)
        if cart_items:

            serializer = CartItemsSerializer(cart_items, many =True)
            return Response(serializer.data)
        else:

            return Response({'message' : 'your cart is empty'})
    


class GetProductIdAPIView(views.APIView):
    def get(self, request, product_id):
        product_response = requests.get(f"{user_url}/api/products/{product_id}").json()
        product_data = product_response.json()
        if 'error' in product_data:
            return HttpResponse(product_data['error'])




class AddToCart(views.APIView):
    def post(self, request):
        cart_response =requests.get(f'{cart_url}/api/cartview/', cookies=request.COOKIES).json()
        cart_id=cart_response['cart_id']

        # Retrieve product_id from the request data, and add the product to the user's cart or increment its quantity if it already exists
        product_id = int(request.data['product_id'])
        if CartItems.objects.filter(cart_id = cart_id, product_id = product_id).first():

            cart_item = CartItems.objects.filter(cart_id=cart_id, product_id=product_id).first()
            cart_item.quantity +=1
            cart_item.save()
            serializer=CartItemsSerializer(cart_item)
        else:

            serializer=CartItemsSerializer(
                data= {
                'cart_id':cart_id,
                'product_id':product_id,
                'quantity':1
                })
            
            serializer.is_valid(raise_exception=True)
            serializer.save()
        return Response(serializer.data)



#Reduces single product quantity in cart          
class DeleteProductAPIView(views.APIView):
    def post(self, request):
        cart_id = requests.get(f'{cart_url}/api/cartview/', cookies=request.COOKIES).json()['cart_id']
        product_id = int(request.data['product_id'])
        cart_item = CartItems.objects.filter(cart_id=cart_id, product_id=product_id).first()
        if cart_item:

            if cart_item.quantity == 1:
                cart_item.delete()
            else:
                cart_item.quantity -= 1
                cart_item.save()


            cart_items = CartItems.objects.filter(product_id=product_id)
            serializer = CartItemsSerializer(cart_items, many=True)
            return Response(serializer.data)
        else:
            return Response({'message': 'product not found in cart'})
        



# deleted product from cart        
class DeleteEntireProductAPIView(views.APIView):
    def post(self, request):
        cart_id = requests.get(f'{cart_url}/api/cartview/', cookies=request.COOKIES).json()['cart_id']
        product_id = int(request.data['product_id'])
        cart_item = CartItems.objects.filter(cart_id=cart_id, product_id=product_id).first()
        if not cart_item:
            return Response({'message': 'Product not found in cart'}, status=status.HTTP_404_NOT_FOUND)
        

        cart_item.delete()
        return Response({'message':'successfully deleted the product'})




# It clears entire cart data
class ClearCartAPIView(views.APIView):
    def post(self, request):
        cart_id = requests.get(f'{cart_url}/api/cartview/', cookies=request.COOKIES).json()['cart_id']
        if cart_id:
            CartItems.objects.filter(cart_id=cart_id).delete()
            return Response({'message': 'Successfully cleared the cart'})
        
        else:
            return Response({'message': 'No cart found to clear'})

