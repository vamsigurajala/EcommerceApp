from rest_framework import generics, views, status
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from .models import Payment, PaymentEvent, Refund
from .serializers import PaymentSerializer, PaymentEventSerializer, RefundSerializer


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
        serializer = PaymentSerializer(data=request.data)
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
