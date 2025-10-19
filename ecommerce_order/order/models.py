from django.db import models
from django.utils import timezone


class Order(models.Model):
    order_id = models.AutoField(primary_key=True)
    user_id = models.BigIntegerField()
    placed_time = models.DateTimeField(auto_now_add=True)
    address_id = models.BigIntegerField()

    # status + amounts
    order_status = models.CharField(max_length=255, default='Not yet placed')
    total_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    order_code   = models.CharField(max_length=20, unique=True, null=True, db_index=True, blank=True)

    # snapshot of the address chosen at checkout <<<
    recipient_name   = models.CharField(max_length=255, blank=True, null=True)
    recipient_phone  = models.CharField(max_length=32,  blank=True, null=True)
    address_label    = models.CharField(max_length=32,  blank=True, null=True)  # e.g. Home/Work
    shipping_address = models.TextField(blank=True, null=True)

    def to_dict(self):
        return {
            'order_id': self.order_id,
            'user_id': self.user_id,
            'order_code': self.order_code,
            'placed_time': self.placed_time.isoformat(),
            'address_id': self.address_id,
            'order_status': self.order_status,
            'total_amount': str(self.total_amount),

            # expose the snapshot so the Home service/template can use it
            'recipient_name':   self.recipient_name or '',
            'recipient_phone':  self.recipient_phone or '',
            'address_label':    self.address_label or '',
            'shipping_address': self.shipping_address or '',
        }

    class Meta:
        indexes = [
            models.Index(fields=['user_id', '-placed_time']),
            models.Index(fields=['user_id']),
            models.Index(fields=['-placed_time']),
        ]


class OrderItems(models.Model):
    order_id  = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="order_items")
    quantity  = models.IntegerField(default=1)
    product_id = models.CharField(max_length=255, db_index=True)
    price     = models.DecimalField(max_digits=10, decimal_places=2)
    discount  = models.DecimalField(max_digits=5, decimal_places=2)

    def to_dict(self):
        return {
            'quantity': self.quantity,
            'product_id': self.product_id,
            'price': str(self.price),
            'discount': str(self.discount),
        }

    class Meta:
        indexes = [
            models.Index(fields=['order_id', 'product_id']),
        ]
