from django.shortcuts import render
from django.http import HttpResponse, request
from rest_framework import views, status
from .models import Cart, CartItems, Wishlist, WishlistItems
from rest_framework.response import Response
from .serializers import WishlistSerializer, WishlistItemsSerializer, CartSerializer,CartItemsSerializer
import json
import requests
from cartproject.settings import user_url, product_url, cart_url, order_url, review_url
from django.db import transaction
from django.db.models import F


def _get_user_id(request):
    return requests.get(f'{user_url}/api/userview/', cookies=request.COOKIES, timeout=6).json()['user_id']

def _get_cart_obj(user_id):
    from .models import Cart
    cart, _ = Cart.objects.get_or_create(user_id=user_id)
    return cart 

# CartAPIView handles GET and POST requests for a user's cart.
class CartAPIView(views.APIView):
    def get(self, request):
        user_id = _get_user_id(request)
        cart, _ = Cart.objects.get_or_create(user_id=user_id)
        return Response(CartSerializer(cart).data)
    @transaction.atomic
    def post(self, request):
        # Delegate to AddToCart logic to avoid two code paths
        return AddToCart().post(request)
  

class CartItemsAPIView(views.APIView):
    def get(self, request):
        user_id = _get_user_id(request)
        cart = _get_cart_obj(user_id)
        cart_items = CartItems.objects.filter(cart_id=cart).order_by('-created_at')
        return Response(CartItemsSerializer(cart_items, many=True).data)

    


class GetProductIdAPIView(views.APIView):
    def get(self, request, product_id):
        r = requests.get(f"{product_url}/api/productview/{product_id}/", cookies=request.COOKIES, timeout=6)
        data = r.json() if r.ok else {'error': 'fetch failed'}
        if 'error' in data:
            return Response(data, status=502)
        return Response(data)


class AddToCart(views.APIView):
    @transaction.atomic
    def post(self, request):
        user_id = _get_user_id(request)
        cart = _get_cart_obj(user_id)

        product_id = int(request.data['product_id'])
        qty = int(request.data.get('quantity', 1) or 1)

        # One row per (cart, product) thanks to unique_together
        ci, created = CartItems.objects.select_for_update().get_or_create(
            cart_id=cart, product_id=product_id,
            defaults={'quantity': max(qty, 1)}
        )
        if not created:
            CartItems.objects.filter(pk=ci.pk).update(quantity=F('quantity') + max(qty, 1))
            ci.refresh_from_db()

        return Response(CartItemsSerializer(ci).data, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)



#Reduces single product quantity in cart          
class DeleteProductAPIView(views.APIView):
    @transaction.atomic
    def post(self, request):
        user_id = _get_user_id(request)
        cart = _get_cart_obj(user_id)

        product_id = int(request.data['product_id'])
        ci = CartItems.objects.select_for_update().filter(cart_id=cart, product_id=product_id).first()
        if not ci:
            return Response({'message': 'product not found in cart'}, status=404)

        if (ci.quantity or 1) <= 1:
            ci.delete()
            return Response({'message': 'removed'})
        else:
            CartItems.objects.filter(pk=ci.pk).update(quantity=F('quantity') - 1)
            ci.refresh_from_db()
            return Response(CartItemsSerializer(ci).data)



# deleted product from cart        
class DeleteEntireProductAPIView(views.APIView):
    @transaction.atomic
    def post(self, request):
        user_id = _get_user_id(request)
        cart = _get_cart_obj(user_id)

        product_id = int(request.data['product_id'])
        deleted, _ = CartItems.objects.filter(cart_id=cart, product_id=product_id).delete()
        if not deleted:
            return Response({'message': 'Product not found in cart'}, status=404)
        return Response({'message': 'successfully deleted the product'})




# It clears entire cart data
class ClearCartAPIView(views.APIView):
    @transaction.atomic
    def post(self, request):
        user_id = _get_user_id(request)
        cart = _get_cart_obj(user_id)
        CartItems.objects.filter(cart_id=cart).delete()
        return Response({'message': 'Successfully cleared the cart'})



class MoveCartToWishlistAPIView(views.APIView):
    @transaction.atomic
    def post(self, request):
        try:
            pid = int(request.data.get('product_id'))
        except (TypeError, ValueError):
            return Response({'ok': False, 'error': 'product_id required'}, status=400)

        try:
            user_id = _get_user_id(request)
        except Exception:
            return Response({'ok': False, 'error': 'auth failed'}, status=401)

        cart = _get_cart_obj(user_id)
        ci = CartItems.objects.select_for_update().filter(cart_id=cart, product_id=pid).first()
        if not ci:
            return Response({'ok': False, 'error': 'not-in-cart'}, status=404)

        qty = max(int(ci.quantity or 1), 1)

        wishlist, _ = Wishlist.objects.get_or_create(user_id=user_id)
        witem, created = WishlistItems.objects.select_for_update().get_or_create(
        wishlist=wishlist, product_id=pid, defaults={'quantity': qty}
        )
        if not created:
            WishlistItems.objects.filter(pk=witem.pk).update(quantity=F('quantity') + qty)


        ci.delete()
        witem.refresh_from_db()
        return Response({'ok': True, 'wishlist_qty': int(witem.quantity)}, status=200)


class WishlistAPIView(views.APIView):
    def get(self, request):
        user_id = _get_user_id(request)
        wishlist, _ = Wishlist.objects.get_or_create(user_id=user_id)
        return Response(WishlistSerializer(wishlist).data)



class WishlistItemsAPIView(views.APIView):
    def get(self, request):
        user_id = _get_user_id(request)
        wishlist = Wishlist.objects.filter(user_id=user_id).first()
        if not wishlist:
            return Response([])
        items = WishlistItems.objects.filter(wishlist=wishlist).order_by('-created_at')
        return Response(WishlistItemsSerializer(items, many=True).data)




class AddToWishlistAPIView(views.APIView):
    @transaction.atomic
    def post(self, request):
        user_id = _get_user_id(request)
        wishlist, _ = Wishlist.objects.get_or_create(user_id=user_id)

        product_id = int(request.data.get('product_id'))
        qty = max(int(request.data.get('quantity', 1) or 1), 1)

        item, created = WishlistItems.objects.select_for_update().get_or_create(
            wishlist=wishlist, product_id=product_id,
            defaults={'quantity': qty}
        )
        if not created:
            WishlistItems.objects.filter(pk=item.pk).update(quantity=F('quantity') + qty)
            item.refresh_from_db()

        return Response(WishlistItemsSerializer(item).data,
                        status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


class RemoveFromWishlistAPIView(views.APIView):
    @transaction.atomic
    def post(self, request):
        user_id = _get_user_id(request)
        product_id = int(request.data.get('product_id'))
        wishlist = Wishlist.objects.filter(user_id=user_id).first()
        if not wishlist:
            return Response({'message':'wishlist empty'}, status=404)
        WishlistItems.objects.filter(wishlist=wishlist, product_id=product_id).delete()
        return Response({'message':'removed'})



class ClearWishlistAPIView(views.APIView):
    @transaction.atomic
    def post(self, request):
        user_id = _get_user_id(request)
        wishlist = Wishlist.objects.filter(user_id=user_id).first()
        if wishlist:
            WishlistItems.objects.filter(wishlist=wishlist).delete()
        return Response({'message':'cleared'})



class MoveWishlistItemToCartAPIView(views.APIView):
    @transaction.atomic
    def post(self, request):
        # robust product_id parsing
        try:
            pid = int(request.data.get('product_id'))
        except (TypeError, ValueError):
            return Response({'ok': False, 'error': 'product_id required'}, status=400)

        # identify user + resources
        try:
            user_id = _get_user_id(request)
        except Exception:
            return Response({'ok': False, 'error': 'auth failed'}, status=401)

        wishlist = Wishlist.objects.filter(user_id=user_id).first()
        if not wishlist:
            return Response({'ok': False, 'error': 'wishlist empty'}, status=404)

        # lock source row
        w_item = WishlistItems.objects.select_for_update().filter(wishlist=wishlist, product_id=pid).first()
        if not w_item:
            # not an exception: report clearly
            return Response({'ok': False, 'error': 'item not in wishlist'}, status=404)

        qty = max(int(w_item.quantity or 1), 1)

        # upsert cart line
        cart = _get_cart_obj(user_id)
        ci, created = CartItems.objects.select_for_update().get_or_create(
        cart_id=cart, product_id=pid, defaults={'quantity': qty}
        )
        if not created:
            CartItems.objects.filter(pk=ci.pk).update(quantity=F('quantity') + qty)


        # remove source
        w_item.delete()

        # read back
        ci.refresh_from_db()
        return Response({'ok': True, 'cart_qty': int(ci.quantity)}, status=200)

    
from rest_framework import status
class IncreaseWishlistQtyAPIView(views.APIView):
    @transaction.atomic
    def post(self, request):
        user_id = _get_user_id(request)
        wishlist = Wishlist.objects.filter(user_id=user_id).first()
        if not wishlist:
            return Response({'message': 'wishlist not found'}, status=404)

        pid = int(request.data.get('product_id'))
        item = WishlistItems.objects.select_for_update().filter(wishlist=wishlist, product_id=pid).first()
        if not item:
            return Response({'message': 'item not found'}, status=404)

        WishlistItems.objects.filter(pk=item.pk).update(quantity=F('quantity') + 1)
        item.refresh_from_db()
        return Response(WishlistItemsSerializer(item).data)

class ReduceWishlistQtyAPIView(views.APIView):
    @transaction.atomic
    def post(self, request):
        user_id = _get_user_id(request)
        wishlist = Wishlist.objects.filter(user_id=user_id).first()
        if not wishlist:
            return Response({'message': 'wishlist not found'}, status=404)

        pid = int(request.data.get('product_id'))
        item = WishlistItems.objects.select_for_update().filter(wishlist=wishlist, product_id=pid).first()
        if not item:
            return Response({'message': 'item not found'}, status=404)

        if (item.quantity or 1) > 1:
            WishlistItems.objects.filter(pk=item.pk).update(quantity=F('quantity') - 1)
            item.refresh_from_db()
            return Response(WishlistItemsSerializer(item).data)
        return Response({'message': 'min quantity is 1'}, status=200)
