from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login as login_user, logout as logout_user
from django.conf import settings
from django.contrib import messages

from logging import getLogger

logger = getLogger(__name__)


# Create your views here.
def login(request):
    if request.method == 'POST':
        form = AuthenticationForm(request=request, data=request.POST)
        logger.debug(form.is_valid())
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')

            user = authenticate(username=username, password=password)
            logger.debug(user)
            if user is not None:
                login_user(request, user)
                return redirect(settings.LOGIN_REDIRECT_URL)
        else:
            messages.error(request, "Invalid username or password.")
    return render(request, 'authentication/login.html')


def logout(request):
    logout_user(request)
    return redirect(settings.LOGOUT_REDIRECT_URL)
