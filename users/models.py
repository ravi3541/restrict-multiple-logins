from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    PermissionsMixin,
)
from django.utils.translation import gettext_lazy as _

from utilities import constants
from .managers import CustomUserManager

class CustomUser(AbstractBaseUser, PermissionsMixin):
    """
    Class for creating model for storing users data.
    """

    first_name = models.CharField(max_length=30, null=False, blank=False)
    last_name = models.CharField(max_length=30, null=False, blank=False)
    email = models.EmailField(_('email address'), unique=True, error_messages={"unique": "This email address is already associated with another account."})
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name", "pt_ft"]

    objects = CustomUserManager()

    def __str__(self):

        return self.email


class BlackListedToken(models.Model):
    """
    Class for storing blacklisted access token.
    """

    token = models.CharField(max_length=500)
    timestamp = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("token",)


class UserDevice(models.Model):
    """
    Class for creating model to for storing users device data.
    """
    access = models.CharField(max_length=300, null=False, blank=False)
    refresh = models.CharField(max_length=300, null=False, blank=False)
    device_id = models.CharField(max_length=50, null=False, blank=False)
    user = models.ForeignKey(CustomUser, null=False, blank=False, on_delete=models.CASCADE)
    device_type = models.CharField(choices=constants.DEVICE_TYPE_CHOICE, max_length=20, null=False, blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
