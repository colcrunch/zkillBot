from django.db import models
from django.contrib.auth.models import User, Permission


# Create your models here.
class UserProfile(models.Model):

    user = models.OneToOneField(
        User,
        related_name='profile',
        on_delete=models.CASCADE
    )
    discord_user_id = models.CharField(
        max_length=255,
        db_index=True,
        null=True,
        help_text="The discord user id for which this token is valid."
    )

    class Meta:
        default_permissions = (())
