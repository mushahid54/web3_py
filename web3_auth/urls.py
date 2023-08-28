from django.conf.urls import url
from . import views
from web3_auth.views import Web3LearningAPIViews, TransferdetailsAPIViews, DecodeSwapTokenAPIViews

urlpatterns = [
    url('authentication', views.authentication, name='authentication'),
    url('request_message', views.request_message, name='request_message'),
    url('my_profile', views.my_profile, name='my_profile'),
    url('verify_message', views.verify_message, name='verify_message'),
    url('decode_swap_token', DecodeSwapTokenAPIViews.as_view(), name='decode_swap_token'),
    # url('authenticate', views.authenticate, name='verify_signature'),
    # url('auth', views.login, name='login'),
    url('checksum_address_details', Web3LearningAPIViews.as_view(), name='checksum_address_details'),
    url('transfer_details', TransferdetailsAPIViews.as_view(), name='transfer_details'),
]