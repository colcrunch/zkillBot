from django.conf.urls import include
from djzkbBot import urls
from django.urls import re_path

urlpatterns = [
    re_path(r'', include(urls)),
]
