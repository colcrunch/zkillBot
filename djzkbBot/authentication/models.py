from django.db import models
from django.contrib.auth.models import User, Permission


# Create your models here.
class UserProfile(models.Model):

    user = models.OneToOneField(
        User,
        related_name='profile',
        on_delete=models.CASCADE
    )

    class Meta:
        default_permissions = (())
