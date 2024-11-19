from django.contrib import admin
from .models import User,UserRole,Address

admin.site.register(User)
admin.site.register(UserRole)
admin.site.register(Address)