from rest_framework import serializers
from .models import Product

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model =  Product
        fields = '__all__'

   
class PaginatedProductSerializer(serializers.Serializer):
    page = serializers.IntegerField()
    pages = serializers.IntegerField()
    results = ProductSerializer(many=True)

class CartProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ('product_name','price','image')