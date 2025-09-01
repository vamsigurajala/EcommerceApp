# reviewproject/serializers.py
from rest_framework import serializers
from django.utils.timezone import localtime
from .models import Review, ReviewReaction, ReviewImage, ReviewVideo   

class ReviewCreateSerializer(serializers.Serializer):
    product_id = serializers.IntegerField()
    rating = serializers.IntegerField(min_value=1, max_value=5)
    title  = serializers.CharField(required=False, allow_blank=True, max_length=120)  # NEW
    body   = serializers.CharField(required=False, allow_blank=True)
    image  = serializers.ImageField(required=False, allow_null=True)

class ReviewUpdateSerializer(serializers.ModelSerializer):           
    class Meta:
        model  = Review
        fields = ("rating", "title", "body", "image")


class ReviewImageSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField()

    class Meta:
        model = ReviewImage
        fields = ("id", "url")

    def get_url(self, obj):
        req = self.context.get("request")
        url = obj.image.url
        return req.build_absolute_uri(url) if req else url

class ReviewSerializer(serializers.ModelSerializer):
    like_count    = serializers.SerializerMethodField()
    dislike_count = serializers.SerializerMethodField()
    image_url     = serializers.SerializerMethodField()
    display_date  = serializers.SerializerMethodField()
    image_urls    = serializers.SerializerMethodField() 
    video_urls    = serializers.SerializerMethodField()

    class Meta:
        model = Review
        fields = "__all__"
        read_only_fields = ("user_id", "user_name", "is_verified_purchase", "created_at", "updated_at")

    
    def get_like_count(self, obj):
        return obj.reactions.filter(value=1).count()

    def get_dislike_count(self, obj):
        return obj.reactions.filter(value=-1).count()
    

    def get_image_urls(self, obj):
        # include legacy single image first if present, then extra images
        urls = []
        # legacy single image:
        single = self.get_image_url(obj)  # your existing helper
        if single:
            urls.append(single)
        # additional images:
        req = self.context.get("request")
        for im in obj.images.all():
            u = im.image.url
            urls.append(req.build_absolute_uri(u) if req else u)
        return urls
    

    def get_image_url(self, obj):
        if not obj.image:
            return None
        req = self.context.get("request")
        url = obj.image.url
        return req.build_absolute_uri(url) if req else url
    
    def get_video_urls(self, obj):
        req = self.context.get("request")
        out = []
        for v in obj.videos.all():
            u = v.video.url
            out.append(req.build_absolute_uri(u) if req else u)
        return out

    def get_display_date(self, obj):
        dt = localtime(obj.created_at)  
        try:
            return dt.strftime("%B %-d, %Y, %-I:%M %p")  # Linux/macOS
        except ValueError:
            return dt.strftime("%B %#d, %Y, %#I:%M %p")  # Windo
        
        
