from django.db import models
from django.utils import timezone


class Payment(models.Model):
    """
    One row per payment attempt for an order.
    Keep only provider tokens/ids—never store raw card data here.
    """
    payment_id = models.AutoField(primary_key=True)

    # references to other services (keep as primitives; no cross-DB foreign keys)
    order_id = models.BigIntegerField(db_index=True)
    user_id = models.BigIntegerField(db_index=True)

    # money
    amount = models.DecimalField(max_digits=12, decimal_places=2)  # e.g., 799.00
    currency = models.CharField(max_length=8, default='INR')

    # provider info
    provider = models.CharField(max_length=50)  # 'razorpay' | 'stripe' | 'mock'
    provider_payment_id = models.CharField(max_length=128, blank=True, null=True, db_index=True)
    payment_method = models.CharField(max_length=50, blank=True, null=True)  # 'card', 'upi', etc.
    receipt_email = models.EmailField(blank=True, null=True)

    # lifecycle
    STATUS_CHOICES = (
        ('REQUIRES_ACTION', 'REQUIRES_ACTION'),
        ('PROCESSING', 'PROCESSING'),
        ('SUCCEEDED', 'SUCCEEDED'),
        ('FAILED', 'FAILED'),
        ('CANCELED', 'CANCELED'),
        ('REFUNDED', 'REFUNDED'),
        ('PARTIALLY_REFUNDED', 'PARTIALLY_REFUNDED'),
    )
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default='REQUIRES_ACTION')

    # idempotency for create/refund calls
    idempotency_key = models.CharField(max_length=64, db_index=True)

    # misc
    description = models.CharField(max_length=255, blank=True, null=True)
    metadata = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'payments'
        indexes = [
            models.Index(fields=['order_id']),
            models.Index(fields=['provider_payment_id']),
            models.Index(fields=['idempotency_key']),
        ]
        unique_together = [
            ('order_id', 'idempotency_key'),  # prevents duplicate charges for same order call
        ]

    def to_dict(self):
        return {
            'payment_id': self.payment_id,
            'order_id': self.order_id,
            'user_id': self.user_id,
            'amount': str(self.amount),
            'currency': self.currency,
            'provider': self.provider,
            'provider_payment_id': self.provider_payment_id,
            'payment_method': self.payment_method,
            'receipt_email': self.receipt_email,
            'status': self.status,
            'idempotency_key': self.idempotency_key,
            'description': self.description,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }


class PaymentEvent(models.Model):
    """
    Append-only audit log for provider webhook/updates (useful for debugging & disputes).
    """
    event_id = models.AutoField(primary_key=True)
    payment = models.ForeignKey(Payment, on_delete=models.CASCADE, related_name='events')

    provider_event_id = models.CharField(max_length=128, db_index=True)
    type = models.CharField(max_length=64)  # e.g., 'payment.succeeded', 'payment.failed'
    payload = models.JSONField()           # raw event from provider
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'payment_events'
        indexes = [
            models.Index(fields=['provider_event_id']),
            models.Index(fields=['type']),
        ]
        unique_together = [
            ('payment', 'provider_event_id'),
        ]

    def to_dict(self):
        return {
            'event_id': self.event_id,
            'payment_id': self.payment_id if hasattr(self, 'payment_id') else self.payment.payment_id,
            'provider_event_id': self.provider_event_id,
            'type': self.type,
            'payload': self.payload,
            'created_at': self.created_at.isoformat(),
        }


class Refund(models.Model):
    """
    Tracks refunds (full or partial) against a Payment.
    """
    refund_id = models.AutoField(primary_key=True)
    payment = models.ForeignKey(Payment, on_delete=models.CASCADE, related_name='refunds')

    amount = models.DecimalField(max_digits=12, decimal_places=2)  # amount refunded
    STATUS_CHOICES = (
        ('REQUESTED', 'REQUESTED'),
        ('SUCCEEDED', 'SUCCEEDED'),
        ('FAILED', 'FAILED'),
    )
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='REQUESTED')

    provider_refund_id = models.CharField(max_length=128, blank=True, null=True, db_index=True)
    reason = models.CharField(max_length=255, blank=True, null=True)
    metadata = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'refunds'
        indexes = [
            models.Index(fields=['provider_refund_id']),
        ]

    def to_dict(self):
        return {
            'refund_id': self.refund_id,
            'payment_id': self.payment.payment_id,
            'amount': str(self.amount),
            'status': self.status,
            'provider_refund_id': self.provider_refund_id,
            'reason': self.reason,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat(),
        }
