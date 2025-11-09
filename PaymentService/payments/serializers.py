from rest_framework import serializers
from .models import Payment, PaymentEvent, Refund


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'


class PaymentEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentEvent
        fields = '__all__'


class RefundSerializer(serializers.ModelSerializer):
    class Meta:
        model = Refund
        fields = '__all__'


# payments/serializers.py
from rest_framework import serializers
from .models import SavedPaymentMethod

class SavedPaymentMethodSerializer(serializers.ModelSerializer):
    class Meta:
        model = SavedPaymentMethod
        fields = (
            "id", "user_id", "provider", "method_type",
            "token", "card_brand", "last4", "exp_month", "exp_year",
            "card_holder_name",          
            "upi_vpa", "upi_provider_name",
            "masked_display", "consented", "is_default", "created_at",
        )
        read_only_fields = ("id", "created_at",)


    def validate(self, attrs):
        mt = attrs.get("method_type")
        if mt == "upi":
            if not attrs.get("upi_vpa"):
                raise serializers.ValidationError("upi_vpa required for method_type=upi")
        elif mt == "card":
            if not attrs.get("last4"):
                raise serializers.ValidationError("last4 required for method_type=card")
        else:
            raise serializers.ValidationError("method_type must be 'upi' or 'card'")
        return attrs

    

    def create(self, validated):
        """
        Allow MULTIPLE methods per user.
        Collapse only exact duplicates:
        - UPI: same user_id + upi_vpa
        - Card: same user_id + brand + last4 + exp_month + exp_year
        Otherwise create a NEW row.
        """
        user_id = validated["user_id"]
        mt = validated["method_type"]

        # ---------- UPI ----------
        if mt == "upi":
            upi_vpa = (validated.get("upi_vpa") or "").strip()
            existing = SavedPaymentMethod.objects.filter(
                user_id=user_id,
                method_type="upi",
                upi_vpa__iexact=upi_vpa,
            ).first()

            if existing:
                existing.masked_display = validated.get("masked_display") or existing.masked_display
                existing.upi_provider_name = validated.get("upi_provider_name") or existing.upi_provider_name
                if validated.get("consented") is not None:
                    existing.consented = validated["consented"]
                if validated.get("is_default") is True:
                    SavedPaymentMethod.objects.filter(
                        user_id=user_id, method_type="upi"
                    ).update(is_default=False)
                    existing.is_default = True
                existing.save(update_fields=["masked_display", "upi_provider_name", "consented", "is_default"])
                return existing

            if not SavedPaymentMethod.objects.filter(user_id=user_id, method_type="upi").exists():
                validated["is_default"] = True
            validated["upi_vpa"] = upi_vpa
            return super().create(validated)

        # ---------- CARD ----------
        if mt == "card":
            brand = (validated.get("card_brand") or "CARD").upper()
            last4 = (validated.get("last4") or "").strip()
            exp_month = validated.get("exp_month")
            exp_year  = validated.get("exp_year")
            holder    = (validated.get("card_holder_name") or "").strip() or None

            existing = SavedPaymentMethod.objects.filter(
                user_id=user_id,
                method_type="card",
                card_brand__iexact=brand,
                last4=last4,
                exp_month=exp_month,
                exp_year=exp_year,
            ).first()

            if existing:
                existing.masked_display = validated.get("masked_display") or existing.masked_display
                if holder is not None:
                    existing.card_holder_name = holder
                if validated.get("consented") is not None:
                    existing.consented = validated["consented"]
                if validated.get("is_default") is True:
                    SavedPaymentMethod.objects.filter(
                        user_id=user_id, method_type="card"
                    ).update(is_default=False)
                    existing.is_default = True
                existing.save(update_fields=["masked_display", "card_holder_name", "consented", "is_default"])
                return existing

            if not SavedPaymentMethod.objects.filter(user_id=user_id, method_type="card").exists():
                validated["is_default"] = True

            validated["card_brand"] = brand
            validated["last4"] = last4
            validated["card_holder_name"] = holder
            return super().create(validated)

        # anything else is invalid
        raise serializers.ValidationError("method_type must be 'upi' or 'card'")
