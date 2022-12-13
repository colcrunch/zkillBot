from django.shortcuts import render

# Create your views here.
def dashboard(request):
    return render(request, 'bot/bot_base.html')


def css_test(request):
    return render(request, 'bot/css_test.html')