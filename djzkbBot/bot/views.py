from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test


# Create your views here.
def is_superuser(user):
    return user.is_superuser

@login_required
def dashboard(request):
    return render(request, 'bot/dashboard.html')


@login_required
@user_passes_test(is_superuser)
def admin(request):
    return render(request, 'bot/admin.html')


def css_test(request):
    return render(request, 'bot/css_test.html')