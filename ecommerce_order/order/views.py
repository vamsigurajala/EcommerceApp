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
        # print(request.POST)
        # print(request.POST['order'])
        orders_data = json.loads(request.POST['order'])
        
        # print(orders_data)
        total_amount = 0
        for cart_item in orders_data['items'] :
            total_amount += float(cart_item['price']) * int(cart_item['quantity'])
        total_amount = '{:.2f}'.format(total_amount)
        # print(total_amount)

        order = Order(
            user_id=orders_data['user_id'],
            address_id=orders_data['address']['address_id'],
            placed_time = datetime.now(),
            total_amount=total_amount,
            order_status = "Placed",
        )
        print(order)
        order.save()

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
    
    def get(self,request):
        user_id = requests.get(f'{user_url}/api/userview/', cookies = request.COOKIES).json()['user_id']
        orders = Order.objects.filter(user_id=user_id,order_status='Placed')
        orderlist=[]
        for order in orders:
            order_data = order.to_dict()
            print(OrderItems.objects.filter(order_id_id = order.order_id)[0].to_dict())
            order_items = [order_item.to_dict() for order_item in OrderItems.objects.filter(order_id_id=order.order_id)]
            order_data['order_items'] = order_items
            orderlist.append(order_data)

        data= {
            "orderlist":orderlist
        }
        data=json.dumps(data)

        # print(data)
        return Response(data)
    

