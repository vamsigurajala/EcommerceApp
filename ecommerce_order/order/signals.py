from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Order
from .utils import gen_order_code

@receiver(post_save, sender=Order)
def assign_order_code(sender, instance: Order, created: bool, **kwargs):
    if created and not instance.order_code:
        code = gen_order_code(instance.pk, instance.placed_time)
        base, i = code, 0
        while Order.objects.filter(order_code=code).exclude(pk=instance.pk).exists():
            i += 1
            code = f"{base[:-2]}{i:02d}"  # very unlikely; tweak last 2 digits
        Order.objects.filter(pk=instance.pk).update(order_code=code)
        instance.order_code = code
