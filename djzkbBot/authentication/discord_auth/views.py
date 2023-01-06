from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings

from .models import Token

from logging import getLogger

logger = getLogger(__name__)


# Create your views here.
def login(request, token):
    pass


def callback(request):
    code = request.GET.get('code')

    token = Token.objects.create_from_code(code)

    return HttpResponse(str(token.__dict__))


def revoke_token(request):
    pass


def refresh_token(request):
    pass
