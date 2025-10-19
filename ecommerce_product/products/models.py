from django.db import models

class Product(models.Model):
    product_id = models.AutoField(primary_key=True)
    product_name = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    product_description = models.TextField(max_length=200,default='')
    category = models.CharField(max_length=255)
    image = models.ImageField(upload_to='media/', blank=True, null=True)
    product_code = models.CharField(max_length=12, unique=True, null=False, blank=False, db_index=True)

    def __str__(self):
        return self.product_name
        

