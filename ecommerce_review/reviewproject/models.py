from django.db import models
from django.core.validators import FileExtensionValidator


class Review(models.Model):
    review_id = models.AutoField(primary_key=True)
    product_id = models.BigIntegerField(db_index=True)
    user_id = models.BigIntegerField(db_index=True)
    user_name = models.CharField(max_length=120, blank=True, default="")
    rating = models.IntegerField()  # 1..5
    image = models.ImageField(upload_to='review_images/', blank=True, null=True)  # NEW
    title = models.CharField(max_length=120, blank=True, default="")
    body = models.TextField(blank=True, default="")
    is_verified_purchase = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)  # Auto adds date & time
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("product_id", "user_id"),)  # one review per user/product
        ordering = ("-created_at",)

    def __str__(self):
        return f"Review {self.review_id} p{self.product_id} u{self.user_id}"


class ReviewReaction(models.Model):
    review = models.ForeignKey(Review, on_delete=models.CASCADE, related_name='reactions')
    user_id = models.BigIntegerField(db_index=True)
    value = models.SmallIntegerField(choices=[(-1, "dislike"), (1, "like")])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (("review", "user_id"),)
        ordering = ("-created_at",)

class ReviewImage(models.Model):
    review = models.ForeignKey(Review, on_delete=models.CASCADE, related_name="images")
    image  = models.ImageField(upload_to='review_images/')
    created_at = models.DateTimeField(auto_now_add=True)

def video_extensions():
    return ["mp4", "webm", "mov", "m4v"]

class ReviewVideo(models.Model):
    review = models.ForeignKey(Review, on_delete=models.CASCADE, related_name="videos")
    video  = models.FileField(
        upload_to='review_videos/',
        validators=[FileExtensionValidator(allowed_extensions=video_extensions())]
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ReviewVideo {self.id} for review {self.review_id}"
