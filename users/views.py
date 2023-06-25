from django.db import transaction
from rest_framework import status
from rest_framework.generics import (
    RetrieveAPIView,
    CreateAPIView,
)
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import TokenError
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import (
    AccessToken,
    RefreshToken
)
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import (
    CustomUser,
    UserDevice,
)
from .serializers import (
    LogoutSerializer,
    GetUserSerializer,
    UserLoginSerializer,
    BlackListSerializer,
    AddUserDeviceSerializer,
    CustomUserSignUpSerializer,
)
from utilities import (
    messages,
    constants
)
from .permissions import IsTokenValid
from .utils import get_tokens_for_user
from utilities.utils import ResponseInfo


class UserSignupAPIView(CreateAPIView):
    """
    Class to create API for signing up users.
    """
    authentication_classes = ()
    permission_classes = ()
    serializer_class = CustomUserSignUpSerializer

    def __init__(self, **kwargs):
        """
        Constructor function for formatting web response to return.
        """
        self.response_format = ResponseInfo().response
        super(UserSignupAPIView, self).__init__(**kwargs)

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        """
        POST method for registering custom user and generation tokens.
        """
        user_serializer = self.get_serializer(data=request.data)
        if user_serializer.is_valid(raise_exception=True):

            user = user_serializer.save()

            user_device_data = {
                "device_id": request.data.get("device_id"),
                "device_type": request.data.get("device_type"),
                "user": user.id,
            }

            jwt_tokens = get_tokens_for_user(user, user_device_data)
            response_data = {
                "user": user_serializer.data,
                "token": jwt_tokens
            }

            self.response_format["status_code"] = status.HTTP_201_CREATED
            self.response_format["data"] = response_data
            self.response_format["error"] = None
            self.response_format["messages"] = [messages.SUCCESS]

        return Response(self.response_format)


class UserLoginAPIView(CreateAPIView):
    """
    Class for creating API view for user login.
    """
    authentication_classes = ()
    permission_classes = ()
    serializer_class = UserLoginSerializer

    def __init__(self, **kwargs):
        """
         Constructor function for formatting the web response to return.
        """
        self.response_format = ResponseInfo().response
        super(UserLoginAPIView, self).__init__(**kwargs)

    def get_queryset(self):
        """
        Method to return custom user queryset.
        """
        email = self.request.data.get("email")
        return CustomUser.objects.get(email=email)

    @transaction.atomic()
    def post(self, request, *args, **kwargs):
        """
        POST Method for validating and logging in the user if valid.
        """
        try:
            user_serializer = self.get_serializer(data=request.data)
            if user_serializer.is_valid(raise_exception=True):
                user = self.get_queryset()

                jwt_token = None
                user_device_data = {
                    "device_id": request.data.get("device_id"),
                    "device_type": request.data.get("device_type"),
                    "user": user.id,
                }

                login_exist = UserDevice.objects.filter(device_id=request.data.get("device_id")).first()
                if login_exist:
                    """
                    if user tries logging in to same device as logged in before,
                    generating tokens and returning
                    """
                    jwt_token = get_tokens_for_user(user, user_device_data)

                else:
                    """
                    if tries to log in through new device,
                    generating token and returning if max allowed devices limit is not reached,
                    else restricting login
                    """
                    logged_in_count = UserDevice.objects.filter(user=user).count()

                    if logged_in_count < constants.ALLOWED_DEVICE_COUNT:

                        jwt_token = get_tokens_for_user(user, user_device_data)
                    else:
                        self.response_format["data"] = None
                        self.response_format["error"] = None
                        self.response_format["status_code"] = status.HTTP_400_BAD_REQUEST
                        self.response_format["message"] = [messages.LOGIN_LIMIT_EXCEEDED.format(constants.ALLOWED_DEVICE_COUNT)]
                        return Response(self.response_format)

                data = {
                    "id": user.id,
                    "token": jwt_token,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                }

                self.response_format["data"] = data
                self.response_format["error"] = None
                self.response_format["status_code"] = status.HTTP_200_OK
                self.response_format["message"] = [messages.LOGIN_SUCCESS]

        except CustomUser.DoesNotExist:
            self.response_format["data"] = None
            self.response_format["error"] = "user"
            self.response_format["status_code"] = status.HTTP_404_NOT_FOUND
            self.response_format["message"] = [messages.UNAUTHORIZED_ACCOUNT]

        return Response(self.response_format)


class UserLogoutAPIView(CreateAPIView):
    """
    Class for creating API view for user logout.
    """
    permission_classes = (IsAuthenticated, IsTokenValid,)
    authentication_classes = (JWTAuthentication,)
    serializer_class = LogoutSerializer

    def __init__(self, **kwargs):
        """
         Constructor function for formatting the web response to return.
        """
        self.response_format = ResponseInfo().response
        super(UserLogoutAPIView, self).__init__(**kwargs)

    @transaction.atomic()
    def post(self, request, *args, **kwargs):
        """
        POST Method for log out and blacklisting the access and refresh token used.
        """
        try:
            auth_header = request.META.get('HTTP_AUTHORIZATION')

            """
            Getting access token from authentication headers and decoding its payload.
            """
            if auth_header:
                key, access_token = auth_header.split(' ')
                decoded_access_token = AccessToken(access_token)
                payload_data = decoded_access_token.payload

                if key == 'Bearer':
                    request.data['token'] = access_token

                    """
                    Taking refresh token from request body and validating it using serializer. 
                    """
                    logout_serializer = self.get_serializer(data=request.data)
                    black_list_access_serializer = BlackListSerializer(data=request.data)

                    if black_list_access_serializer.is_valid(raise_exception=True) and logout_serializer.is_valid(raise_exception=True):
                        """
                        if both serializers are valid, 
                        blacklist access and refresh token and delete user device info from user device model. 
                        """
                        # deleting user device info
                        user_device = UserDevice.objects.filter(device_id=payload_data["device_id"], device_type=payload_data["device_type"], user=request.user.id)
                        user_device.delete()

                        # blacklist access token
                        black_list_access_serializer.save()

                        # blacklist refresh token
                        token = RefreshToken(request.data["refresh"])
                        token.blacklist()


                        self.response_format["data"] = None
                        self.response_format["error"] = None
                        self.response_format["status_code"] = status.HTTP_200_OK
                        self.response_format["message"] = [messages.LOGOUT_SUCCESS]
                else:
                    self.response_format["data"] = None
                    self.response_format["error"] = "user"
                    self.response_format["status_code"] = status.HTTP_403_FORBIDDEN
                    self.response_format["message"] = [messages.TOKEN_NOT_FOUND]
            else:
                self.response_format["data"] = None
                self.response_format["error"] = "user"
                self.response_format["status_code"] = status.HTTP_403_FORBIDDEN
                self.response_format["message"] = [messages.TOKEN_NOT_FOUND]
        except TokenError:
            self.response_format["data"] = None
            self.response_format["error"] = "Refresh token"
            self.response_format["status_code"] = status.HTTP_400_BAD_REQUEST
            self.response_format["message"] = [messages.INVALID_TOKEN]
        return Response(self.response_format)


class RefreshTokenAPIView(CreateAPIView):
    """
    Class for creating API to generate access token from refresh token.
    """
    permission_classes = ()
    authentication_classes = ()

    def __init__(self, **kwargs):
        """
         Constructor function for formatting the web response to return.
        """
        self.response_format = ResponseInfo().response
        super(RefreshTokenAPIView, self).__init__(**kwargs)

    @transaction.atomic()
    def post(self, request, *args, **kwargs):
        """
        POST method to generate new access tokens using refresh token.
        """
        try:
            """
            Getting refresh token from authentication header.
            """
            auth_header = request.META.get('HTTP_AUTHORIZATION')
            if auth_header:
                key, refresh_token = auth_header.split(' ')

                if key == 'Bearer':

                    # generating new access token from refresh token.
                    token = RefreshToken(refresh_token)
                    access_token = str(token.access_token)

                    # getting refresh tokens payload
                    token_payload = token.payload

                    # getting user device object
                    user_device_obj = UserDevice.objects.filter(refresh=token, user=token_payload["user_id"], device_id=token_payload["device_id"]).first()

                    # blacklisting old access token
                    blacklist_old_access = BlackListSerializer(data={"token":user_device_obj.access})
                    if blacklist_old_access.is_valid(raise_exception=True):
                        blacklist_old_access.save()

                    # updating user device object with new access token
                    update_user_device = AddUserDeviceSerializer(user_device_obj, data={"access":access_token}, partial=True)
                    if update_user_device.is_valid(raise_exception=True):
                        update_user_device.save()

                    data = {
                        "access": access_token
                    }
                    self.response_format["data"] = data
                    self.response_format["error"] = None
                    self.response_format["status_code"] = status.HTTP_201_CREATED
                    self.response_format["message"] = [messages.SUCCESS]

                else:
                    self.response_format["data"] = None
                    self.response_format["error"] = "Bearer Error"
                    self.response_format["status_code"] = status.HTTP_400_BAD_REQUEST
                    self.response_format["message"] = [messages.TOKEN_NOT_FOUND]
        except CustomUser.DoesNotExist:
            self.response_format["data"] = None
            self.response_format["error"] = "User Error"
            self.response_format["status_code"] = status.HTTP_400_BAD_REQUEST
            self.response_format["message"] = [messages.DOES_NOT_EXISTS.format("User")]

        except TokenError:
            self.response_format["data"] = None
            self.response_format["error"] = "Refresh token"
            self.response_format["status_code"] = status.HTTP_400_BAD_REQUEST
            self.response_format["message"] = [messages.INVALID_TOKEN]

        return Response(self.response_format)


class GetUserAPIView(RetrieveAPIView):
    permission_classes = (IsAuthenticated, IsTokenValid,)
    authentication_classes = (JWTAuthentication,)
    serializer_class = GetUserSerializer

    def __init__(self, **kwargs):
        """
         Constructor function for formatting the web response to return.
        """
        self.response_format = ResponseInfo().response
        super(GetUserAPIView, self).__init__(**kwargs)

    def get_queryset(self):
        user = self.request.user
        return CustomUser.objects.get(id=user.id)

    def get(self, request, *args, **kwargs):
        user = self.get_queryset()
        serializer = self.get_serializer(user)
        self.response_format["data"] = serializer.data
        self.response_format["error"] = None
        self.response_format["status_code"] = status.HTTP_200_OK
        self.response_format["message"] = [messages.SUCCESS]

        return Response(self.response_format)