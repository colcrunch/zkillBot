from django.urls import path

from . import views

app_name = "dauth"

urlpatterns = [
    path('login/', views.login, name='login'),
    path('callback/', views.callback, name='discord_callback'),
    path('token/revoke/', views.revoke_token, name='revoke_token'),
    path('token/refresh/', views.refresh_token, name='refresh_token'),
]