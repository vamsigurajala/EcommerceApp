from django.db import models
from django.utils.timezone import now


class Cart(models.Model):
    cart_id = models.AutoField(primary_key=True)
    user_id = models.CharField(max_length=255)

    def __str__(self):
        return self.cart_id


class CartItems(models.Model):
    cart_id = models.ForeignKey(Cart, on_delete=models.CASCADE)
    product_id = models.BigIntegerField()
    quantity = models.IntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.product_id} * {self.quantity}"
