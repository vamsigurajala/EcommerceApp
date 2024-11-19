from collections import OrderedDict
from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseBadRequest
from .models import Product
from rest_framework.views import APIView
from inventory.models import Inventory
import requests
from rest_framework.response import Response
from django.http import JsonResponse
from .serializers import ProductSerializer, CartProductSerializer
from .serializers import PaginatedProductSerializer
from rest_framework.viewsets import ModelViewSet
from rest_framework.decorators import api_view
from rest_framework.decorators import permission_classes
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics, filters
from rest_framework.pagination import LimitOffsetPagination
from rest_framework import views, status
from productservice.settings import user_url, product_url, cart_url, order_url, review_url

# Create your views here.


class PageSizePagination(PageNumberPagination): 
    page_size = 2 #default pagesize is 2

    def get_paginated_response(self, data):
        return Response(OrderedDict((
            ('page', self.page.number),
            ('pages', self.page.paginator.num_pages),
            ('next', self.get_next_link()),
            ('previous', self.get_previous_link()),
            ('results', data)
        )))



class ProductSearchAPIView(generics.ListAPIView):
    # Set model and serializer for the API view
    queryset = Product.objects.all()
    serializer_class = ProductSerializer

    # Use custom pagination class to set page size and response format
    pagination_class = PageSizePagination

    # Enable search and filtering on specified fields
    filter_backends = [filters.SearchFilter, DjangoFilterBackend]
    search_fields = ['product_name', 'product_description', 'category']
    filterset_fields = ['product_name', 'product_description', 'category']

    def get_queryset(self):
        # Get queryset with filter and search if query parameters are provided
        queryset = super().get_queryset()
        search_query = self.request.query_params.get('search', None)
        if search_query:
            queryset = queryset.filter(product_name__icontains=search_query)
        return queryset
  


class Get_ProductAPIView(ModelViewSet):
    serializer_class = ProductSerializer
    queryset = Product.objects.all()
    pagination_class = PageSizePagination

    def products_with_id(request, id):
        # Retrieve products with a specific seller id
        product = Product.objects.filter(seller_id=id)
        serializer=ProductSerializer(product, many=True)
        return Response(serializer.data)
    


class Pagination(PageNumberPagination):  #This is for Home Page Pagination
    page_size = 6

    def get_paginated_response(self, data):
        return Response(OrderedDict((
            ('page', self.page.number),
            ('pages', self.page.paginator.num_pages),
            ('next', self.get_next_link()),
            ('previous', self.get_previous_link()),
            ('results', data)
        )))
    


class SearchAPIView(generics.ListAPIView): #This is for searching products in Home Page 
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    pagination_class = Pagination
    filter_backends = [filters.SearchFilter, DjangoFilterBackend]
    search_fields = ['product_name', 'product_description', 'category']
    filterset_fields = ['product_name', 'product_description', 'category']

    def get_queryset(self):
        queryset = super().get_queryset()
        search_query = self.request.query_params.get('searchproduct', None)
        if search_query:
            queryset = queryset.filter(product_name__icontains=search_query)
        return queryset
     



class Set_ProductAPIView(ModelViewSet):
    serializer_class = ProductSerializer
    queryset = Product.objects.all()
    pagination_class = Pagination

    def products_with_id(request, id):
         product = Product.objects.filter(seller_id=id)
         serializer=ProductSerializer(product, many=True)
         return Response(serializer.data)




class AllProductAPIView(APIView):  #To retrieve all the products details
    def get(self, request):
        product= Product.objects.all()
        serializer = ProductSerializer(product , many=True, context={'request':request})
        return Response(serializer.data)



    
def product_category(request, category=None):
    products=Product.objects.all()
    serializer = ProductSerializer(products, many=True, context={'request':request})
    return Response(serializer.data)
    



# GetProductIdAPIView retrieves a single product's ID and returns a list of all product IDs in the database.
class GetProductIdAPIView(views.APIView):
    def get(self, request, *args, **kwargs):
        product_id = kwargs['product_id']         # Get the product object that matches the requested ID.
        product = Product.objects.get(product_id = product_id)
        #return Response(ProductSerializer(product).data)
        product_ids = Product.objects.all().values_list('product_id', flat=True)
        print(product_ids)
        return Response(product_ids)



# ProductAPIView retrieves a single product object based on its ID and returns serialized data.
class ProductAPIView(APIView):
    def get(self, request, product_id, **kwargs):
        product = Product.objects.get(product_id=product_id)
        serializer = CartProductSerializer(product, context={'request':request})
        print(serializer)
        return Response(serializer.data)




# SingleProductAPIView retrieves a single product object based on its ID and returns serialized data.
class SingleProductAPIView(APIView):
    def get(self, request, product_id, **kwargs):
        product = Product.objects.get(product_id=product_id)
        serializer = ProductSerializer(product, context={'request':request})
        #print(serializer)
        return Response(serializer.data)
