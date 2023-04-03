from django.urls import path,include 
from . import views
from . views import OrderAPIVew, OrderItemsAPIView , PlaceOrderView , ClearOrderAPIView


urlpatterns = [
    path("order/",views.order, name="ordermsg"),
    path("orderdata/",OrderAPIVew.as_view(), name="getproducts"),
    path('orderitems/', OrderItemsAPIView.as_view(), name="orderitems"),
    path('placeorder/', PlaceOrderView.as_view(), name="placeorder"),
    path('clearorders/', ClearOrderAPIView.as_view(), name="clearorders"),
]



