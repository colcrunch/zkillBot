import logging

from django.contrib.auth.models import User
from django.db.models.signals import pre_save, post_save, pre_delete, post_delete, m2m_changed
from django.dispatch import receiver, Signal

from .models import UserProfile


logger = logging.getLogger(__name__)


@receiver(post_save, sender=User)
def create_required_models(sender, instance, created, *args, **kwargs):
    # ensure a userprofile is always created
    if created:
        logger.debug(f"User {instance} created. Creating default UserProfile.")
        UserProfile.objects.get_or_create(user=instance)
