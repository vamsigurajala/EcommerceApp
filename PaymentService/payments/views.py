from rest_framework import generics, views, status
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from .utils import generate_txn_id 
from .models import Payment, PaymentEvent, Refund
from .serializers import PaymentSerializer, PaymentEventSerializer, RefundSerializer
from rest_framework import permissions
from django.db import transaction
from .models import SavedPaymentMethod
from .serializers import SavedPaymentMethodSerializer


# List / create / get payments
class PaymentAPIView(generics.ListCreateAPIView):
    queryset = Payment.objects.all()
    serializer_class = PaymentSerializer


class PaymentDetailAPIView(generics.RetrieveAPIView):
    queryset = Payment.objects.all()
    serializer_class = PaymentSerializer
    lookup_field = "payment_id"


# Create a new payment intent (client will call this when placing order)
@method_decorator(csrf_exempt, name="dispatch")
class PaymentIntentAPIView(views.APIView):
    def post(self, request):
        payload = request.data.copy()

        # ensure a transaction id exists for every new Payment
        if not payload.get("transaction_id"):
            payload["transaction_id"] = generate_txn_id()

        serializer = PaymentSerializer(data=payload)
        if serializer.is_valid():
            payment = serializer.save(status="REQUIRES_ACTION")
            return Response(PaymentSerializer(payment).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# Webhook to update payment status (called by provider like Razorpay/Stripe)
@method_decorator(csrf_exempt, name="dispatch")
class PaymentWebhookAPIView(views.APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request, *args, **kwargs):
        data = request.data
        provider_payment_id = data.get("provider_payment_id")
        event_type = data.get("event_type", "payment.succeeded")

        try:
            payment = Payment.objects.get(provider_payment_id=provider_payment_id)
            if event_type == "payment.succeeded":
                payment.status = "SUCCEEDED"
            elif event_type == "payment.failed":
                payment.status = "FAILED"
            payment.save()

            PaymentEvent.objects.create(
                payment=payment,
                provider_event_id=data.get("event_id", "evt_mock"),
                type=event_type,
                payload=data,
            )
            return Response({"message": "Webhook processed"}, status=status.HTTP_200_OK)

        except Payment.DoesNotExist:
            return Response({"error": "Payment not found"}, status=status.HTTP_404_NOT_FOUND)

class TxLookupAPIView(views.APIView):
    def get(self, request, transaction_id):
        p = Payment.objects.filter(transaction_id=transaction_id).first()
        if not p:
            return Response({"error": "not found"}, status=404)
        return Response(PaymentSerializer(p).data)

# >>> ADD: Saved methods endpoints
from rest_framework import permissions
from .models import SavedPaymentMethod
from .serializers import SavedPaymentMethodSerializer

@method_decorator(csrf_exempt, name="dispatch")
class SavedPaymentMethodListCreate(generics.ListCreateAPIView):
    serializer_class = SavedPaymentMethodSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        qs = SavedPaymentMethod.objects.all().order_by('-is_default', '-created_at')
        user_id = self.request.query_params.get('user_id')
        if user_id:
            qs = qs.filter(user_id=user_id)
        return qs

@method_decorator(csrf_exempt, name="dispatch")
class SavedPaymentMethodDelete(generics.DestroyAPIView):
    serializer_class = SavedPaymentMethodSerializer
    permission_classes = [permissions.AllowAny]
    queryset = SavedPaymentMethod.objects.all()

    def perform_destroy(self, instance):
        # (optional) enforce user ownership via ?user_id=
        req_uid = self.request.query_params.get('user_id')
        if req_uid and str(instance.user_id) != str(req_uid):
            raise PermissionError("user mismatch")
        return super().perform_destroy(instance)

@method_decorator(csrf_exempt, name="dispatch")
class SavedPaymentMethodSetDefault(views.APIView):
    permission_classes = [permissions.AllowAny]

    def patch(self, request, pk):
        # expects ?user_id=...&type=card|upi
        user_id = request.query_params.get('user_id')
        method_type = request.query_params.get('type')
        if not (user_id and method_type):
            return Response({"error": "user_id and type required"}, status=400)

        try:
            target = SavedPaymentMethod.objects.get(pk=pk, user_id=user_id, method_type=method_type)
        except SavedPaymentMethod.DoesNotExist:
            return Response({"error": "not found"}, status=404)

        SavedPaymentMethod.objects.filter(user_id=user_id, method_type=method_type).update(is_default=False)
        target.is_default = True
        target.save()
        return Response(SavedPaymentMethodSerializer(target).data)
