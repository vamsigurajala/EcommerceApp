from django.db import models
from django.utils import timezone


# Create your models here.

class Order(models.Model):
    order_id = models.AutoField(primary_key=True)
    user_id = models.BigIntegerField()
    placed_time = models.DateTimeField(auto_now_add=True)
    address_id=models.BigIntegerField()
    order_status = models.CharField(max_length=255, default='Not yet placed')
    total_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)

    # def __str__(self):
    #     return self.order_id
    def to_dict(self):
        return {
            'order_id': self.order_id,
            'user_id':self.user_id,
            'placed_time':self.placed_time.isoformat(),
            'address_id':self.address_id,
            'order_status':self.order_status,
            'total_amount':str(self.total_amount)

        }

class OrderItems(models.Model):
    order_id = models.ForeignKey(Order, on_delete=models.CASCADE)
    quantity=models.IntegerField(default=1)
    product_id = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    discount = models.DecimalField(max_digits=5, decimal_places=2)

    def to_dict(self):
        return {
        'quantity':self.quantity,
        'product_id':self.product_id,
        'price':str(self.price),
        'discount':str(self.discount),
        }
        
