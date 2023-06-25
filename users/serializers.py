from rest_framework import serializers
from django.contrib.auth import authenticate

from utilities import constants
from .models import (
    CustomUser,
    UserDevice,
    BlackListedToken
)


class CustomUserSignUpSerializer(serializers.ModelSerializer):
    """
    Serializer class for signing up users.
    """
    device_id = serializers.CharField(max_length=50, allow_null=False, allow_blank=False, read_only=True)
    device_type = serializers.ChoiceField(allow_null=False, allow_blank=False, choices=constants.DEVICE_TYPE_CHOICE, read_only=True)

    class Meta:
        model = CustomUser
        fields = ("id", "first_name", "last_name", "email", "device_id", "device_type", "password", "created_at", "updated_at")
        extra_kwargs = {
            "password": {"write_only": True}
        }

    def validate_password(self, password):
        """
        Function for validating password.
        """
        password_length = len(password)

        if not 8 <= password_length <= 15:
            raise serializers.ValidationError("Password length should be between 8 and 15.")
        return password

    def create(self, validated_data):
        """
        Function for creating and returning the created instance
        based on the validated data of the user.
        """
        user = CustomUser.objects.create_user(
            first_name=validated_data.pop('first_name'),
            last_name=validated_data.pop('last_name'),
            email=validated_data.pop('email'),
            password=validated_data.pop('password'),
        )
        return user


class UserLoginSerializer(serializers.Serializer):
    """
    Class for authorizing user for correct login credentials.
    """
    email = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

    default_error_messages = {
        'invalid_credentials': 'Email id or password is invalid.',
    }

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    def __init__(self, *args, **kwargs):
        """
        Constructor Function for initializing UserLoginSerializer.
        """
        super(UserLoginSerializer, self).__init__(*args, **kwargs)
        self.user = None

    def validate(self, attrs):
        """
        Function to validate user credentials.
        """
        self.user = authenticate(username=attrs.pop("email"), password=attrs.pop('password'))
        if self.user:
            return attrs
        else:
            raise serializers.ValidationError(self.error_messages['invalid_credentials'])


class LogoutSerializer(serializers.Serializer):
    """
    Serializer class for logout.
    """

    refresh = serializers.CharField(max_length=300, required=True, allow_null=False, allow_blank=False)


class BlackListSerializer(serializers.ModelSerializer):
    """
    Serializer class for blacklisting access tokens.
    """

    class Meta:
        model = BlackListedToken
        fields = ("token",)


class AddUserDeviceSerializer(serializers.ModelSerializer):
    """
    Serializer class to save user device details.
    """

    class Meta:
        model = UserDevice
        fields = ("id", "access", "refresh", "device_id", "device_type", "user", "created_at", "updated_at")


class GetUserSerializer(serializers.ModelSerializer):
    """
    Serializer class for getting user details.
    """

    class Meta:
        model = CustomUser
        fields = ("id", "first_name", "last_name", "email")