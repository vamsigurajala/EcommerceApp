from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Product
from .views import gen_product_code   # or from .utils import gen_product_code

@receiver(post_save, sender=Product)
def assign_code(sender, instance: Product, created, **kwargs):
    if not created:
        return
    if instance.product_code:
        return
    code = gen_product_code(instance.pk)
    base = code
    i = 0
    from django.db.models import Q
    while Product.objects.filter(product_code=code).exists():
        i += 1
        code = f"{base[:-2]}{i:02d}"
    Product.objects.filter(pk=instance.pk).update(product_code=code)

