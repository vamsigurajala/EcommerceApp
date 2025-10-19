# cart/models.py
from django.db import models
from django.db.models import Q


class Cart(models.Model):
    cart_id = models.AutoField(primary_key=True)
    user_id = models.CharField(max_length=255)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        # If you frequently fetch by user_id, index it for O(1) lookup.
        indexes = [
            models.Index(fields=['user_id']),
        ]

    def __str__(self):
        return str(self.cart_id)


class CartItems(models.Model):
    """
    One row per (cart, product). Enforced by unique_together.
    Composite index gives O(1) point-lookups for add/inc/dec/remove.
    """
    cart_id = models.ForeignKey(Cart, on_delete=models.CASCADE)
    product_id = models.BigIntegerField()

    # Keep quantity non-negative with a DB constraint (see Meta.constraints).
    quantity = models.PositiveIntegerField(default=1)

    # Optional but highly recommended:
    # snapshot the price at add time to avoid product-service calls for totals.
    unit_price = models.DecimalField(
        max_digits=10, decimal_places=2, null=True, blank=True
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        # Ensure only one line per product per cart
        unique_together = (('cart_id', 'product_id'),)

        # Composite index to make filter(cart_id=?, product_id=?) use a single index
        indexes = [
            models.Index(fields=['cart_id', 'product_id']),
        ]

        # Guard against invalid quantities (you can still delete the row when qty would go to 0)
        constraints = [
            models.CheckConstraint(
                check=Q(quantity__gte=1),
                name='cartitem_qty_gte_1',
            ),
        ]

    def __str__(self):
        return f"{self.product_id} * {self.quantity}"


class Wishlist(models.Model):
    wishlist_id = models.AutoField(primary_key=True)
    user_id = models.CharField(max_length=255)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['user_id']),
        ]

    def __str__(self):
        return f"Wishlist<{self.wishlist_id}> user={self.user_id}"


class WishlistItems(models.Model):
    wishlist = models.ForeignKey(
        Wishlist, on_delete=models.CASCADE, related_name='items'
    )
    product_id = models.BigIntegerField()
    quantity = models.PositiveIntegerField(default=1)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # You already had this — keep it to avoid dup lines in wishlist
        unique_together = (('wishlist', 'product_id'),)

        # Explicit composite index (unique_together will also create a unique index)
        indexes = [
            models.Index(fields=['wishlist', 'product_id']),
        ]

        constraints = [
            models.CheckConstraint(
                check=Q(quantity__gte=1),
                name='wishlistitem_qty_gte_1',
            ),
        ]

    def __str__(self):
        return f"{self.product_id}"
