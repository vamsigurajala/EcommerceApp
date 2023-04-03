from django.shortcuts import render,redirect
from django.http import HttpResponse, HttpResponseBadRequest
from products.models import Product
from rest_framework.views import APIView
#from .serializers import ProductSerializer
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import Inventory
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from django.http import JsonResponse
# Create your views here.

def inventory(request):
    return HttpResponse('inventory service')
    
   
def add_products(request):
    if request.method == 'POST':
        # Validate the received data
        product = request.POST.get('product')
        count = request.POST.get('count')
        last_stocked = request.POST.get('last_stocked')
        discount = request.POST.get('discount')

        # if not (product_name and product_description and price and category and image):
        #     return JsonResponse({'error': 'Missing required fields'}, status=400)

        try:
            price = float(price)
        except ValueError:
            return JsonResponse({'error': 'Invalid price'}, status=400)

        product= Product(product_name= request.POST['product_name'], 
                        product_description= request.POST['product_description'], 
                        price=request.POST['price'],
                        category=request.POST['category'],
                        image= request.POST['image']) 
        
        product.save()
        return JsonResponse({'id': product.id,
                                'product_name': product.product_name,
                                'product_description': product.product_description,
                                'price': product.price,
                                'category': product.category,
                                'image': product.image}, status=201)

    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    

# class Get_The_ProductAPIView(APIView):
#     def get(self,request):
#         products = Product.objects.all()
#         serializer = ProductSerializer(products, many=True)
#         return Response(serializer.data)
        
# class All_ProductAPIView(APIView):
#     def post(self, request):
#         # Check if the user is a seller
#         if not request.user.is_authenticated or not request.user.is_seller:
#             return HttpResponseBadRequest("You are not authorized to perform this action.")
        
#         # Create and validate the Product serializer
#         serializer = ProductSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         product = serializer.save(seller=request.user)
#         inventory = Inventory.objects.create(
#             product=product,
#             count=request.data.get('count', 0),
#             discount=request.data.get('discount', 0.00)
#         )
#         serialized_product = ProductSerializer(product)
#         return Response(serialized_product.data)



