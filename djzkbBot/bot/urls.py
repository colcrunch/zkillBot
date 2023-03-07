from django.urls import path

from . import views

app_name = "bot"

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('admin/', views.admin, name='admin'),
    path('css_test/', views.css_test, name='css_test'),
]