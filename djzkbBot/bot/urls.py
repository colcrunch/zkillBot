from django.urls import path

from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('css_test/', views.css_test, name='css_test'),
]