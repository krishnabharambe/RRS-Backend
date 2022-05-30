from django.urls import path,include
from . import views

urlpatterns = [
    path('index/',views.index),
    path('ValidatePhone/',views.ValidatePhoneSendOTP.as_view()),
    path('ValidateOTP/',views.ValidateOTP.as_view()),
    path('register/',views.Register.as_view()),
    path('registerTech/',views.RegisterTech.as_view()),
    path('login/',views.LoginAPI.as_view()),
    path('loginTech/',views.LoginTechAPI.as_view()),
    path('userAPI/',views.UserAPI.as_view()),
    path('changePassword/', views.ChangePasswordAPI.as_view()),
    path('ValidatePhoneForgot/', views.ValidatePhoneForgot.as_view()),
    path('ForgotValidateOTP/', views.ForgotValidateOTP.as_view()),
    path('ForgetPasswordChange/', views.ForgetPasswordChange.as_view()),


    path('allSlidercards/', views.allSlidercards, name="allSlidercards"),
    path('allServicesList/', views.allServicesList),
    path('MainServicesList/', views.MainServicesList),
    path('Services4/', views.Services4),
    path('allServicesList/<service>/', views.serviceOrList),
    path('allServicesList4/<service>/', views.serviceOrList4),
    path('allsubSubService/', views.allsubSubService),
    path('SubService/<service>/', views.SubServiceView),

    path('allRequests/<statusui>/', views.allRequests, name="allRequests"),
    path('requests/add/', views.RV_requests, name="RV_requests"),
    path('requests/', views.getUserRequests.as_view(), name="getUserRequests"),
    path('request/<id>/', views.getRequest.as_view(), name="getRequest"),
    path('CancelBooking/<id>/', views.CancelBooking.as_view(), name="CancelBooking"),

    path('profile/', views.myProfile.as_view(), name="myProfile"),
    path('myProfileUpdate/', views.myProfileUpdate.as_view(), name='myProfileUpdate'),

    path('getallAssignedBookings/', views.getallAssignedBookings.as_view()),

    path('getAllStaff/', views.getStaff.as_view(), name="getStaff"),


]
