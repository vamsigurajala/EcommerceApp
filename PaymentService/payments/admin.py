from django.contrib import admin
from .models import Payment, PaymentEvent, Refund

@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ("payment_id", "transaction_id", "order_id", "user_id", "amount", "status", "created_at")
    search_fields = ("transaction_id", "order_id", "user_id", "provider_payment_id", "idempotency_key")
    list_filter = ("status", "provider", "currency", "created_at")
