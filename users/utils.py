from datetime import datetime
from rest_framework.views import exception_handler
from rest_framework_simplejwt.tokens import TokenError

from .models import UserDevice
from .serializers import BlackListSerializer


from rest_framework_simplejwt.tokens import AccessToken,RefreshToken
from .serializers import AddUserDeviceSerializer

def get_tokens_for_user(user, extra_data):
    refresh = RefreshToken.for_user(user)
    # adding more data to tokens
    refresh["device_id"] = extra_data["device_id"]
    refresh["device_type"] = extra_data["device_type"]

    token = {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

    extra_data["access"] = token["access"]
    extra_data["refresh"] = token["refresh"]

    login_exist = UserDevice.objects.filter(device_id=extra_data.get("device_id")).first()
    if login_exist:
        # if someone is already logged in through requested device, logging out that user.

        """
        checking if tokens issued for that old user on requested device are expired or not, 
        if not expired blaclisting both access and refresh tokens.
        """
        try:
            refresh_expiry = RefreshToken(login_exist.refresh).payload.get("exp")
            if refresh_expiry > datetime.now().timestamp():
                print("refresh token not expired")
                RefreshToken(login_exist.refresh).blacklist()
            else:
                print("refresh token expired")

            access_expiry = AccessToken(login_exist.access).payload.get("exp")
            if access_expiry > datetime.now().timestamp():
                blacklist_access = BlackListSerializer(data={"token": login_exist.access})
                blacklist_access.is_valid(raise_exception=True)
                blacklist_access.save()
                print("access token not expired")
            else:
                print("access token expired")
        except TokenError:
            # do nothing if tokens are expired
            print("Do nothing")

        # deleting old user's device related from user device model.
        login_exist.delete()

    """
    if no logged in user was found on requested device, 
    save new users data and device info in user device model 
    """
    user_device_serializer = AddUserDeviceSerializer(data=extra_data)
    if user_device_serializer.is_valid(raise_exception=True):
        user_device_serializer.save()

    return token


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is not None:
        customized_response = dict()
        customized_response['error'] = []

        for key, value in response.data.items():
            error = key
            customized_response['status_code'] = response.status_code
            customized_response['error'] = error
            customized_response['data'] = None
            if response.status_code == 401:
                if type(value[0]) is dict:
                    customized_response['message'] = [value[0]["message"]]
                else:
                    customized_response['message'] = [value]
            else:
                if type(value) is list:
                    customized_response['message'] = [value[0]]
                else:
                    customized_response['message'] = [value]

        response.data = customized_response

    return response
