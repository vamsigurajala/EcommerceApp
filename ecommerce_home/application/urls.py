from django.urls import path
from . import views
from .views import UserDetailsView, GetUserIdAPIView, UserLoginAPIView, LogoutView, AddressView


from drf_yasg.views import get_schema_view 
from drf_yasg import openapi

schema_view = get_schema_view(
     openapi.Info( 
        title="User API", 
        default_version="v1", 
        description="Welcome to User API", 
        contact=openapi.Contact(email="abc@abc.com"), 
        license=openapi.License(name="License"),
    ), 
    public=True, 
    ) 
urlpatterns = [

    path( "swagger/", schema_view.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui", ),


    path('', views.landing_page,name='landing_page'),
    path('homepage/', views.homepage, name='homepage'),
    path('usersignup/', views.usersignup,name='usersignup'),
    path('address/', views.useraddress, name='addingaddress'),
    path('products/',views.products, name='productshome'),
    path('paginate/', views.paginate, name='paginatedproducts'),
    path('getuserid/<int:user_id>/',GetUserIdAPIView.as_view(), name="getuserid"),
    path('userview/', UserDetailsView.as_view(),name="userview"),
    path('login/',UserLoginAPIView.as_view(),name="loginuser"),
    path('logout',LogoutView.as_view(),name="logout"),
    path('getaddress/', AddressView.as_view(), name='address'),
    path('allproducts/', views.product_info, name='allproducts'),
    path('orderaddress/', views.order_address, name='orderaddress'),
    path('cart/', views.cart, name='cart'),
    path('addquantity/', views.add_quantity, name="addquantity"),
    path('reducequantity/', views.reduce_quantity, name="reducequantity"),
    path('deleteproduct/', views.delete_product, name="deleteproduct"),
    path('clearcart/', views.clear_cart, name="clearcart"),
    path('getuseraddress/', views.get_user_address, name='useraddress'),
    path('checkout/', views.checkout, name='checkout'),
    path("vieworders/", views.vieworders, name='vieworder'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    # path('review/<int:product_id>/',views.write_review,name='writereview'),
    # path('seereviews/', views.product_reviews, name='seereviews'),

]