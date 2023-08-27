from django.conf.urls import url
from . import views
from web3_auth.views import Web3LearningAPIViews, TransferdetailsAPIViews, UniSwapAllPairs

urlpatterns = [
    url('moralis_auth', views.moralis_auth, name='moralis_auth'),
    url('request_message', views.request_message, name='request_message'),
    url('my_profile', views.my_profile, name='my_profile'),
    url('verify_message', views.verify_message, name='verify_message'),
    # url('authenticate', views.authenticate, name='verify_signature'),
    # url('auth', views.login, name='login'),
    url('checksum_address_details', Web3LearningAPIViews.as_view(), name='checksum_address_details'),
    url('transfer_details', TransferdetailsAPIViews.as_view(), name='transfer_details'),
    url('uniswap_all_pairs', UniSwapAllPairs.as_view(), name='uniswap_all_pairs'),
]