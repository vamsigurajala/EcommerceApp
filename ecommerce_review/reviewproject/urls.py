from django.urls import path
from .views import health, ReviewListCreateAPIView, ReviewVoteAPIView, ReviewDetailAPIView, MyReviewAPIView,ReviewStatsAPIView

urlpatterns = [
    path("health/", health, name="health"),
    path("reviews/", ReviewListCreateAPIView.as_view(), name="reviews-list-create"),
    path('reviews/<int:pk>/', ReviewDetailAPIView.as_view(), name='review-detail'),  
    path('reviews/<int:review_id>/vote/', ReviewVoteAPIView.as_view(), name='review-vote'),
    path("reviews/mine/", MyReviewAPIView.as_view(), name="review-mine"),  
    path("reviews/stats/", ReviewStatsAPIView.as_view(), name="reviews-stats"),
]
