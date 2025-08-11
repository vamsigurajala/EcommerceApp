import json
import requests
from collections import OrderedDict
from django.conf import settings
from django.db.models import Avg, Count, Q
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.parsers import JSONParser
from rest_framework.generics import RetrieveUpdateDestroyAPIView
from rest_framework.permissions import AllowAny
from reviewservice.settings import user_url, product_url, cart_url, order_url, review_url
from .models import Review, ReviewReaction, ReviewImage
from .serializers import ReviewSerializer, ReviewCreateSerializer, ReviewUpdateSerializer as ReviewUpdateSer


def health(request):
    from django.http import JsonResponse
    return JsonResponse({"ok": True})



def _get_current_user_payload(request) -> dict:
    r = requests.get(f"{user_url}/api/userview/", cookies=request.COOKIES, timeout=10)
    try:
        data = r.json()
    except Exception:
        raise PermissionError("Not authenticated")
    if not isinstance(data, dict) or not data.get("user_id"):
        raise PermissionError("Not authenticated")
    return data

def _get_current_user_id(request) -> int:
    return int(_get_current_user_payload(request)["user_id"])

def _get_current_user_name(request) -> str:
    data = _get_current_user_payload(request)
    # Single name preferred; fallbacks: username, "User <id>"
    name = (data.get("name") or data.get("username") or "").strip()
    return name or f"User {data.get('user_id')}"


def _user_has_purchased_product(product_id: int, request) -> bool:
    try:
        user_id = _get_current_user_id(request)
    except PermissionError:
        print("[REVIEWS] no auth for purchase check")
        return False

    try:
        url = f"{order_url}/api/internal/has-purchased/"
        params = {"user_id": str(user_id), "product_id": str(product_id)}
        r = requests.get(url, params=params, timeout=5)
        ct = r.headers.get("content-type","")
        print("[REVIEWS] order check", url, params, "->", r.status_code)
        if not r.ok or "application/json" not in ct:
            return False
        data = r.json()
        print("[REVIEWS] order says:", data)
        return bool(data.get("has_purchased"))
    except requests.RequestException as e:
        print("[REVIEWS] order check error:", e)
        return False



    
class MyReviewAPIView(APIView):
    """
    GET /api/reviews/mine/?product_id=123
    Returns the logged-in user's review for that product, or null.
    """
    def get(self, request):
        try:
            user_id = _get_current_user_id(request)
        except PermissionError:
            return Response({"ok": False, "auth": False}, status=401)

        product_id = request.query_params.get("product_id")
        if not product_id:
            return Response({"error": "product_id is required"}, status=400)

        rv = Review.objects.filter(user_id=user_id, product_id=product_id).first()
        if not rv:
            return Response({"ok": True, "review": None}, status=200)

        data = ReviewSerializer(rv, context={'request': request}).data
        return Response({"ok": True, "review": data}, status=200)
    

    
class ReviewsPagination(PageNumberPagination):
    page_size = 2
    def get_paginated_response(self, data):
        return Response(OrderedDict((
            ("page", self.page.number),
            ("pages", self.page.paginator.num_pages),
            ("count", self.page.paginator.count),
            ("next", self.get_next_link()),
            ("previous", self.get_previous_link()),
            ("results", data),
        )))



class ReviewListCreateAPIView(APIView):
    """
    GET  /api/reviews/?product_id=123
    POST /api/reviews/   (multipart or form-encoded)
          fields: product_id, rating, title?, body?, image?
    """
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    pagination_class = ReviewsPagination

    # list
    def get(self, request):
        product_id = request.query_params.get("product_id")
        if not product_id:
            return Response({"error": "product_id is required"}, status=400)

        qs = Review.objects.filter(product_id=product_id).order_by("-created_at")
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(qs, request)
        data = ReviewSerializer(page, many=True, context={'request': request}).data
        return paginator.get_paginated_response(data)

    # create
    def post(self, request):
        try:
            user_id = _get_current_user_id(request)
            user_name = _get_current_user_name(request)
        except PermissionError:
            return Response({"error": "Not authenticated"}, status=401)

        s = ReviewCreateSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        product_id = s.validated_data["product_id"]

        if Review.objects.filter(user_id=user_id, product_id=product_id).exists():
            # helpful conflict body for FE
            existing = Review.objects.filter(user_id=user_id, product_id=product_id).only("review_id").first()
            return Response(
                {"error": "You already reviewed this product", "existing_review_id": existing.review_id},
                status=409
            )

    # Enforce verified-only
        print("[REVIEWS] create: user_id", user_id, "product_id", product_id)
        if not _user_has_purchased_product(product_id, request):
            print("[REVIEWS] blocked: not verified")
            return Response({"error":"You must purchase this product before leaving a review."}, status=403)

        
        review = Review.objects.create(
            user_id=user_id,
            user_name=user_name,
            product_id=product_id,
            rating=s.validated_data["rating"],
            title=s.validated_data.get("title", ""),
            body=s.validated_data.get("body", ""),
            is_verified_purchase=True,
            image=request.FILES.get("image")
        )

         # save multiple images (new)
        for f in request.FILES.getlist('images'):
            ReviewImage.objects.create(review=review, image=f)

        # (optional) also mirror the legacy single 'image' into the gallery table
        single = request.FILES.get("image")
        if single:
            ReviewImage.objects.create(review=review, image=single)
        
        print("[REVIEWS] created review", review.review_id, "verified:", review.is_verified_purchase)
        return Response(ReviewSerializer(review, context={'request': request}).data, status=201)



class ReviewDetailAPIView(RetrieveUpdateDestroyAPIView):
    """
    GET    /api/reviews/<pk>/
    PATCH  /api/reviews/<pk>/  (only author can edit)
    PUT    /api/reviews/<pk>/  (only author)
    DELETE /api/reviews/<pk>/  (only author)
    """
    queryset = Review.objects.all()
    serializer_class = ReviewUpdateSer
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    def get_permissions(self):
        # Public GET; author checks enforced for write ops
        return [AllowAny()]
    
    def get_serializer_class(self):
        if self.request.method == "GET":
            return ReviewSerializer  
        return ReviewUpdateSer
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        ser = ReviewSerializer(instance, context={'request': request})
        return Response(ser.data, status=200)

    def update(self, request, *args, **kwargs):
        # author check
        try:
            user_id = _get_current_user_id(request)
        except PermissionError:
            return Response({"error": "Not authenticated"}, status=401)

        review = self.get_object()
        if int(review.user_id) != int(user_id):
            return Response({"error": "You can only edit your own review"}, status=403)

        partial = request.method.lower() == "patch"
        serializer = self.get_serializer(review, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        new_multi = request.FILES.getlist('images')  # multi-input
        new_single = request.FILES.get('image')      # legacy single

        if new_multi or new_single:
            # delete gallery images
            for im in review.images.all():
                try:
                    # remove file from storage first (optional but cleaner)
                    if im.image:
                        im.image.delete(save=False)
                except Exception:
                    pass
                im.delete()

            # clear legacy single image field (and file)
            if review.image:
                try:
                    review.image.delete(save=False)
                except Exception:
                    pass
                review.image = None
                review.save(update_fields=['image'])

            # add back new images
            for f in new_multi:
                ReviewImage.objects.create(review=review, image=f)

            if new_single:
                # keep legacy field in sync + mirror into gallery so UI sees it
                review.image = new_single
                review.save(update_fields=['image'])
                ReviewImage.objects.create(review=review, image=new_single)
        # --------- /REPLACE BEHAVIOR ----------

        # Return full read serializer for FE convenience (includes image_urls)
        return Response(ReviewSerializer(review, context={'request': request}).data, status=200)
        
    def destroy(self, request, *args, **kwargs):
        try:
            user_id = _get_current_user_id(request)
        except PermissionError:
            return Response({"error": "Not authenticated"}, status=401)

        review = self.get_object()
        if int(review.user_id) != int(user_id):
            return Response({"error": "You can only delete your own review"}, status=403)

        return super().destroy(request, *args, **kwargs)
    
    

class ReviewVoteAPIView(APIView):
    def post(self, request, review_id):
        try:
            user_id = _get_current_user_id(request)
        except PermissionError:
            return Response({"ok": False, "auth": False}, status=401)

        try:
            review = Review.objects.get(pk=review_id)
        except Review.DoesNotExist:
            return Response({"ok": False, "error": "not found"}, status=404)

        try:
            val = int(request.data.get('value'))
        except Exception:
            return Response({"ok": False, "error": "bad value"}, status=400)
        if val not in (1, -1):
            return Response({"ok": False, "error": "bad value"}, status=400)

        reaction, created = ReviewReaction.objects.get_or_create(
            review=review, user_id=user_id, defaults={'value': val}
        )
        action = 'created'
        if not created:
            if reaction.value == val:
                reaction.delete()
                action = 'cleared'
            else:
                reaction.value = val
                reaction.save(update_fields=['value'])
                action = 'switched'

        like_count = ReviewReaction.objects.filter(review=review, value=1).count()
        dislike_count = ReviewReaction.objects.filter(review=review, value=-1).count()

        return Response({"ok": True, "action": action, "like_count": like_count, "dislike_count": dislike_count, "review_id": review_id}, status=200)


class ReviewStatsAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        pid = request.GET.get("product_id")
        if not pid:
            return Response({"error": "product_id is required"}, status=400)

        qs = Review.objects.filter(product_id=pid)
        total = qs.count()
        avg = qs.aggregate(a=Avg("rating"))["a"] or 0
        # Use your PK field name: review_id (NOT "id")
        buckets = qs.aggregate(
            c1=Count("review_id", filter=Q(rating=1)),
            c2=Count("review_id", filter=Q(rating=2)),
            c3=Count("review_id", filter=Q(rating=3)),
            c4=Count("review_id", filter=Q(rating=4)),
            c5=Count("review_id", filter=Q(rating=5)),
        )
        return Response({
            "total": total,
            "average": round(avg, 1),
            "counts": {
                "1": buckets["c1"], "2": buckets["c2"], "3": buckets["c3"],
                "4": buckets["c4"], "5": buckets["c5"],
            }
        }, status=200)