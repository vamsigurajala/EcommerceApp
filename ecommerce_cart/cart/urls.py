from django.urls import path
from . import views
from .views import (
    CartItemsAPIView, CartAPIView, AddToCart, DeleteEntireProductAPIView,
    DeleteProductAPIView, ClearCartAPIView, GetProductIdAPIView,
    WishlistAPIView, WishlistItemsAPIView, AddToWishlistAPIView, ReduceWishlistQtyAPIView, MoveCartToWishlistAPIView,
    RemoveFromWishlistAPIView, ClearWishlistAPIView, MoveWishlistItemToCartAPIView,IncreaseWishlistQtyAPIView,
)
from drf_yasg.views import get_schema_view 
from drf_yasg import openapi

schema_view = get_schema_view(
     openapi.Info( 
        title="Cart API", 
        default_version="v1", 
        description="Welcome to Cart API", 
        contact=openapi.Contact(email="abc@abc.com"), 
        license=openapi.License(name="License"),
    ), 
    public=True, 
    ) 
urlpatterns = [

    path( "swagger/", schema_view.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui", ),


    path("cartview/", CartAPIView.as_view(), name="cartview"),
    path("cartitems/",CartItemsAPIView.as_view(), name="cartitems"),
    path('getproducts/', GetProductIdAPIView.as_view(), name='getproducts'),
    path("addtocart/", AddToCart.as_view(), name="addtocart"),
    path("reducequantity/", DeleteProductAPIView.as_view(), name="reducequantity"),
    path("deleteproduct/", DeleteEntireProductAPIView.as_view(), name="deleteproduct"),
    path("clearcart/", ClearCartAPIView.as_view(), name="clearcart"),
    path("wishlist/", WishlistAPIView.as_view(), name="wishlist"),
    path("wishlistitems/", WishlistItemsAPIView.as_view(), name="wishlistitems"),
    path("addtowishlist/", AddToWishlistAPIView.as_view(), name="addtowishlist"),
    path("removewishlist/", RemoveFromWishlistAPIView.as_view(), name="removewishlist"),
    path("clearwishlist/", ClearWishlistAPIView.as_view(), name="clearwishlist"),
    path("move-wishlist-to-cart/", MoveWishlistItemToCartAPIView.as_view(), name="move_wishlist_to_cart"),
    path("wishlist/addquantity/", IncreaseWishlistQtyAPIView.as_view(), name="wishlist_addquantity"),
    path("wishlist/reducequantity/", ReduceWishlistQtyAPIView.as_view(), name="wishlist_reducequantity"),
    path("move-cart-to-wishlist/", MoveCartToWishlistAPIView.as_view(), name="move_cart_to_wishlist"),

]


