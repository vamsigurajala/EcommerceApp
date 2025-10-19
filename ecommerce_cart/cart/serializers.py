from rest_framework import serializers
from .models import Cart, CartItems, Wishlist, WishlistItems

class CartSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cart 
        fields = '__all__'

class CartItemsSerializer(serializers.ModelSerializer):
    class Meta:
        model = CartItems
        fields = '__all__'

class WishlistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wishlist
        fields = '__all__'

class WishlistItemsSerializer(serializers.ModelSerializer):
    class Meta:
        model = WishlistItems
        fields = '__all__'