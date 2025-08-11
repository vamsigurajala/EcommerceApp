from django.db import models
from products.models import Product



class Inventory(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    count = models.IntegerField(default=0)
    last_stocked = models.DateField(auto_now_add=True)
    discount = models.DecimalField(max_digits=4, decimal_places=2, default=0.00)

    # def __str__(self):
    #     return f'{self.product.product_name} - Count: {self.count}'
