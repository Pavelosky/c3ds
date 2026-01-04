from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class UserProfile(models.Model):
    class UserType(models.TextChoices):
        ADMIN = 'ADMIN', 'Administrator'
        PARTICIPANT = 'PARTICIPANT', 'System Participant'
        NON_PARTICIPANT = 'NON_PARTICIPANT', 'Non-Participant'

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    user_type = models.CharField(
        max_length=20,
        choices=UserType.choices,
        default=UserType.NON_PARTICIPANT
    )

    def __str__(self):
        return f"{self.user.username} ({self.get_user_type_display()})"


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
