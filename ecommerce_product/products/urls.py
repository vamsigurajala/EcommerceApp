from django.urls import path
from . import views
from .views import  Get_ProductAPIView, GetProductIdAPIView, ProductAPIView, AllProductAPIView, SearchAPIView, Set_ProductAPIView, SingleProductAPIView

from drf_yasg.views import get_schema_view 
from drf_yasg import openapi

schema_view = get_schema_view(
     openapi.Info( 
        title="Product API", 
        default_version="v1", 
        description="Welcome to Product API", 
        contact=openapi.Contact(email="abc@abc.com"), 
        license=openapi.License(name="License"),
    ), 
    public=True, 
    ) 
urlpatterns = [

    path( "swagger/", schema_view.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui", ),

    path('getproducts/', Get_ProductAPIView.as_view({'get': 'list'})),
    #path('products/', views.ProductAPIView.as_view(), name='products'),
    path('productsearch/', views.ProductSearchAPIView.as_view(), name='product_search_api'),
    path('getproductid/<int:product_id>/', GetProductIdAPIView.as_view(), name='getproductid'),
    path('productview/<int:product_id>/', ProductAPIView.as_view(), name='productview'),
    path('allproducts/', AllProductAPIView.as_view(), name='allproducts'),
    path('singleproduct/<int:product_id>/', SingleProductAPIView.as_view(), name='singleproduct'),
    path('homepage/', SearchAPIView.as_view(), name='homepage'),
    path('setproducts/', Set_ProductAPIView.as_view({'get': 'list'})),

]
