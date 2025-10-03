from django.urls import path
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from .views import PaymentAPIView, PaymentDetailAPIView, PaymentIntentAPIView, PaymentWebhookAPIView

schema_view = get_schema_view(
    openapi.Info(
        title="Payments API",
        default_version="v1",
        description="Payments microservice API",
        contact=openapi.Contact(email="abc@abc.com"),
        license=openapi.License(name="License"),
    ),
    public=True,
)

urlpatterns = [
    path("swagger/", schema_view.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui"),
    path("payments/intents/", PaymentIntentAPIView.as_view()),          # <--- slash
    path("payments/webhook/", PaymentWebhookAPIView.as_view()),         # <--- slash
    path("payments/", PaymentAPIView.as_view()),                        # <--- slash
    path("payments/<int:payment_id>/", PaymentDetailAPIView.as_view()), # <--- slash
]
