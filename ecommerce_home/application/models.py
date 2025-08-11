from django.db import models
from django.contrib.auth.models import AbstractUser

class UserRole(models.Model):
    role_id = models.AutoField(primary_key=True,unique=True)
    role_name = models.CharField(max_length=50)

class User(AbstractUser):
    user_id = models.AutoField(primary_key=True, unique=True)
    username = models.CharField(max_length=50)
    email = models.EmailField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    age = models.IntegerField()
    gender = models.CharField(max_length=10)
    user_role = models.ForeignKey(UserRole, on_delete=models.CASCADE, null=True)

    USERNAME_FIELD='email'
    REQUIRED_FIELDS=['username','age','gender']



class Address(models.Model):
    address_id = models.AutoField(primary_key=True,unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    door_no = models.CharField(max_length=10)
    street = models.CharField(max_length=255)
    area = models.CharField(max_length=255)
    city = models.CharField(max_length=255)
    state = models.CharField(max_length=255)
    pincode = models.CharField(max_length=10)
    country = models.CharField(max_length=255)
