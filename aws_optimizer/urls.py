from django.urls import path
from .views import get_all_compute_optimizer_recommendations
from .views import get_s3_bucket_details, get_aws_resources
from .views import register_user, login_user, logout_user

urlpatterns = [
    path('compute-optimizer/all/', get_all_compute_optimizer_recommendations),
    path('s3-details/', get_s3_bucket_details, name='s3-details'),
    path('ebs-ss-eip-details/', get_aws_resources),
    path('register/', register_user, name='register'),
    path('login/', login_user, name='login'),
    path('logout/', logout_user, name='logout'),
]
