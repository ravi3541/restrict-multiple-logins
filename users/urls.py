from django.urls import path
from .views import (
    GetUserAPIView,
    UserSignupAPIView,
    UserLoginAPIView,
    UserLogoutAPIView,
    RefreshTokenAPIView,
)


urlpatterns = [
    path("register", UserSignupAPIView.as_view(), name="user-signup"),
    path("login", UserLoginAPIView.as_view(), name="user-login"),
    path("logout", UserLogoutAPIView.as_view(), name="user-logout"),
    path("refreshToken", RefreshTokenAPIView.as_view(), name="refresh-token"),
    path("getUser", GetUserAPIView.as_view(), name="get-user")
]