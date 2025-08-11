from django.urls import path, include
from . import views
urlpatterns = [
    path('inventory/',views.inventory,name="inventory page"),
]
