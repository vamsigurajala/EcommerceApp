from django.urls import path
from . import views
from .views  import  CartItemsAPIView, CartAPIView,AddToCart,DeleteEntireProductAPIView,DeleteProductAPIView,ClearCartAPIView, GetProductIdAPIView
urlpatterns = [
    path("cartfunc/", views.cartfun, name="cartfunction"),
    path("cartview/", CartAPIView.as_view(), name="cartview"),
    path("cartitems/",CartItemsAPIView.as_view(), name="cartitems"),
    path('getproducts/', GetProductIdAPIView.as_view(), name='getproducts'),
    path("addtocart/", AddToCart.as_view(), name="addtocart"),
    path("reducequantity/", DeleteProductAPIView.as_view(), name="reducequantity"),
    path("deleteproduct/", DeleteEntireProductAPIView.as_view(), name="deleteproduct"),
    path("clearcart/", ClearCartAPIView.as_view(), name="clearcart"),


]
