from django.urls import path,include 
from . import views
from . views import OrderAPIVew, OrderItemsAPIView , PlaceOrderView 


from drf_yasg.views import get_schema_view 
from drf_yasg import openapi

schema_view = get_schema_view(
     openapi.Info( 
        title="Order API", 
        default_version="v1", 
        description="Welcome to Order API", 
        contact=openapi.Contact(email="abc@abc.com"), 
        license=openapi.License(name="License"),
    ), 
    public=True, 
    ) 
urlpatterns = [

    path( "swagger/", schema_view.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui", ),
    path("orderdata/",OrderAPIVew.as_view(), name="getproducts"),
    path('orderitems/', OrderItemsAPIView.as_view(), name="orderitems"),
    path('placeorder/', PlaceOrderView.as_view(), name="placeorder"),
]



