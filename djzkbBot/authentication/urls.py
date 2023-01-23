from django.urls import path, include

from . import views
from .discord_auth import urls

app_name = "authentication"

urlpatterns = [
    path('login/', views.login, name="login"),
    path('logout/', views.logout, name="logout"),
    path('discord/', include((urls, 'discord_auth'), namespace='discord_auth'))
]