from django.shortcuts import render
from django.contrib.auth.decorators import login_required

# Create your views here.
@login_required
def dashboard(request):
    return render(request, 'bot/dashboard.html')


@login_required
def admin(request):
    return render(request, 'bot/admin.html')


def css_test(request):
    return render(request, 'bot/css_test.html')