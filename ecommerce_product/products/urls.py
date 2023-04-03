from django.urls import path
from . import views
from .views import  Get_ProductAPIView, GetProductIdAPIView, ProductAPIView, AllProductAPIView, SearchAPIView, Set_ProductAPIView, SingleProductAPIView


urlpatterns = [
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
