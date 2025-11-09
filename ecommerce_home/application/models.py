from django.db import models
from django.contrib.auth.models import AbstractUser

class UserRole(models.Model):
    role_id = models.AutoField(primary_key=True,unique=True)
    role_name = models.CharField(max_length=50)

class User(AbstractUser):
    user_id = models.AutoField(primary_key=True, unique=True)
    user_code = models.CharField(max_length=32, unique=True, db_index=True, null=True, blank=True)
    username = models.CharField(max_length=50)
    email = models.EmailField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    age = models.IntegerField()
    gender = models.CharField(max_length=10)
    phone = models.CharField(max_length=15, blank=True, null=True)
    pan_card = models.CharField(max_length=15, blank=True, null=True)
    user_role = models.ForeignKey(UserRole, on_delete=models.CASCADE, null=True)

    USERNAME_FIELD='email'
    REQUIRED_FIELDS=['username','age','gender']

ADDRESS_TYPE_CHOICES = (
    ('HOME', 'Home'),
    ('WORK', 'Work (10 AM - 8 PM)'),
)

class Address(models.Model):
    name = models.CharField(max_length=100, blank=True, null=True)         
    phone = models.CharField(max_length=15, blank=True, null=True)
    address_id = models.AutoField(primary_key=True,unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    door_no = models.CharField(max_length=10)
    street = models.CharField(max_length=255)
    area = models.CharField(max_length=255)
    city = models.CharField(max_length=255)
    state = models.CharField(max_length=255)
    pincode = models.CharField(max_length=10)
    country = models.CharField(max_length=255)
    landmark = models.CharField(max_length=255, blank=True, null=True)      
    alt_phone = models.CharField(max_length=15, blank=True, null=True)      
    tag = models.CharField(max_length=10, choices=ADDRESS_TYPE_CHOICES,default='HOME')
    created_at = models.DateTimeField(auto_now_add=True)                   
    updated_at = models.DateTimeField(auto_now=True) 
