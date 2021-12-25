from django.urls import path,include
from . import views

urlpatterns = [
    path('index/',views.index),
    path('ValidatePhone/',views.ValidatePhoneSendOTP.as_view()),
    path('ValidateOTP/',views.ValidateOTP.as_view()),
    path('register/',views.Register.as_view()),
    path('login/',views.LoginAPI.as_view()),
    path('userAPI/',views.UserAPI.as_view()),
    path('changePassword/', views.ChangePasswordAPI.as_view()),
    path('ValidatePhoneForgot/', views.ValidatePhoneForgot.as_view()),
    path('ForgotValidateOTP/', views.ForgotValidateOTP.as_view()),
    path('ForgetPasswordChange/', views.ForgetPasswordChange.as_view()),


    path('allSlidercards/', views.allSlidercards, name="allSlidercards"),
    path('allServicesList/', views.allServicesList),
    path('MainServicesList/', views.MainServicesList),
    path('allServicesList/<service>/', views.serviceOrList),
    path('SubService/<service>/', views.SubServiceView),

    path('allRequests/', views.allRequests, name="allRequests"),
    path('requests/add/', views.RV_requests, name="RV_requests"),
    path('requests/', views.getUserRequests, name="getUserRequests")

]
