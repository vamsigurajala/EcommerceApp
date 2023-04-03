from rest_framework import serializers
from .models import Cart, CartItems

class CartSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cart 
        fields = '__all__'

class CartItemsSerializer(serializers.ModelSerializer):
    class Meta:
        model = CartItems
        fields = '__all__'