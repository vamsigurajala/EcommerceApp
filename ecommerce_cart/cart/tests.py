from django.test import TestCase
from .models import Cart, CartItems
from .views import *
from django.test import TestCase, Client
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

# Create your tests here.


class CartModelTestCase(TestCase):
    def setUp(self):
        Cart.objects.create(user_id=11)

    def test_cart_str_method(self):
        cart = Cart.objects.get(user_id=11)
        print(cart.user_id.isdigit())
        self.assertTrue(cart.user_id.isdigit())
        # self.assertEqual(str(cart), str(cart.cart_id))
        

class CartItemsModelTestCase(TestCase):
    def setUp(self):
        cart = Cart.objects.create(user_id='user_id')
        CartItems.objects.create(cart_id=cart, product_id=1, quantity=2)

    def test_cart_item_str_method(self):
        cart_item = CartItems.objects.get(product_id=1)
        self.assertEqual(str(cart_item), '1 * 2')

