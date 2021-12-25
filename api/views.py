from django.shortcuts import get_object_or_404, render
import random
# Create your views here.
from rest_framework import permissions, generics, status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.db.models import Q
from api.models import M_Services, M_SubServices, R_Requests, SliderImageModel, User, PhoneOTP
from rest_framework.views import APIView
from .serializers import (CreateTechUserSerializer, CreateUserSerializer, ChangePasswordSerializer, M_ServicesSerializer, M_SubServicesSerializer, R_RequestsSSerializer, R_RequestsSerializer, SliderImageModelSerializer,
                          UserSerializer, LoginUserSerializer, ForgetPasswordSerializer)
from knox.auth import TokenAuthentication
from knox.views import LoginView as KnoxLoginView
from django.contrib.auth import login

def index(request):
    pass

class ForgetPasswordChange(APIView):
    '''
    if forgot_logged is valid and account exists then only pass otp, phone and password to reset the password. All three should match.APIView
    '''

    def post(self, request, *args, **kwargs):
        phone = request.data.get('phone', False)
        otp = request.data.get("otp", False)
        password = request.data.get('password', False)

        if phone and otp and password:
            old = PhoneOTP.objects.filter(
                Q(phone__iexact=phone) & Q(otp__iexact=otp))
            if old.exists():
                old = old.first()
                if old.forgot_logged:
                    post_data = {
                        'phone': phone,
                        'password': password
                    }
                    user_obj = get_object_or_404(User, phone__iexact=phone)
                    serializer = ForgetPasswordSerializer(data=post_data)
                    serializer.is_valid(raise_exception=True)
                    if user_obj:
                        user_obj.set_password(serializer.data.get('password'))
                        user_obj.active = True
                        user_obj.save()
                        old.delete()
                        return Response({
                            'status': True,
                            'detail': 'Password changed successfully. Please Login'
                        })

                else:
                    return Response({
                        'status': False,
                        'detail': 'OTP Verification failed. Please try again in previous step'
                    })

            else:
                return Response({
                    'status': False,
                    'detail': 'Phone and otp are not matching or a new phone has entered. Request a new otp in forgot password'
                })

        else:
            return Response({
                'status': False,
                'detail': 'Post request have parameters mising.'
            })


class ForgotValidateOTP(APIView):
    '''
    If you have received an otp, post a request with phone and that otp and you will be redirected to reset  the forgotted password
    '''

    def post(self, request, *args, **kwargs):
        phone = request.data.get('phone', False)
        otp_sent = request.data.get('otp', False)

        if phone and otp_sent:
            old = PhoneOTP.objects.filter(phone__iexact=phone)
            if old.exists():
                old = old.first()
                if old.forgot == False:
                    return Response({
                        'status': False,
                        'detail': 'This phone havenot send valid otp for forgot password. Request a new otp or contact help centre.'
                    })

                otp = old.otp
                if str(otp) == str(otp_sent):
                    old.forgot_logged = True
                    old.save()

                    return Response({
                        'status': True,
                        'detail': 'OTP matched, kindly proceed to create new password'
                    })
                else:
                    return Response({
                        'status': False,
                        'detail': 'OTP incorrect, please try again'
                    })
            else:
                return Response({
                    'status': False,
                    'detail': 'Phone not recognised. Kindly request a new otp with this number'
                })

        else:
            return Response({
                'status': 'False',
                'detail': 'Either phone or otp was not recieved in Post request'
            })


class ValidatePhoneForgot(APIView):
    '''
    Validate if account is there for a given phone number and then send otp for forgot password reset'''

    def post(self, request, *args, **kwargs):
        phone_number = request.data.get('phone')
        if phone_number:
            phone = str(phone_number)
            user = User.objects.filter(phone__iexact=phone)
            if user.exists():
                otp = send_otp_forgot(phone)
                print(phone, otp)
                if otp:
                    otp = str(otp)
                    count = 0
                    old = PhoneOTP.objects.filter(phone__iexact=phone)
                    if old.exists():
                        old2 = old.first()
                        k = old2.count
                        count = old.first().count
                        old.update(count=count + 1)
                        old.update(otp=otp)
                        if k > 500:
                            return Response({
                                'status': False,
                                'detail': 'Maximum otp limits reached. Kindly support our customer care or try with different number'
                            })

                        return Response({'status': True, 'detail': 'OTP has been sent for password reset. Limits about to reach.'})

                    else:
                        count = count + 1

                        PhoneOTP.objects.create(
                            phone=phone,
                            otp=otp,
                            count=count,
                            forgot=True,

                        )
                        return Response({'status': True, 'detail': 'OTP has been sent for password reset'})

                else:
                    return Response({
                                    'status': 'False', 'detail': "OTP sending error. Please try after some time."
                                    })
            else:
                return Response({
                    'status': False,
                    'detail': 'Phone number not recognised. Kindly try a new account for this number'
                })


class ChangePasswordAPI(generics.UpdateAPIView):
    """
    Change password endpoint view
    """
    authentication_classes = (TokenAuthentication, )
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.IsAuthenticated, ]

    def get_object(self, queryset=None):
        """
        Returns current logged in user instance
        """
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            if not self.object.check_password(serializer.data.get('password_1')):
                return Response({
                    'status': False,
                    'current_password': 'Does not match with our data',
                }, status=status.HTTP_400_BAD_REQUEST)

            self.object.set_password(serializer.data.get('password_2'))
            self.object.password_changed = True
            self.object.save()
            return Response({
                "status": True,
                "detail": "Password has been successfully changed.",
            })

        return Response(serializer.error, status=status.HTTP_400_BAD_REQUEST)

        
class UserAPI(generics.RetrieveAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = [permissions.IsAuthenticated, ]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user


class LoginAPI(KnoxLoginView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = LoginUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        if user.last_login is None:
            user.first_login = True
            user.save()

        elif user.first_login:
            user.first_login = False
            user.save()

        login(request, user)
        return super().post(request, format=None)

class Register(APIView):

    '''Takes phone and a password and creates a new user only if otp was verified and phone is new'''

    def post(self, request, *args, **kwargs):
        phone = request.data.get('phone', False)
        password = request.data.get('password', False)

        if phone and password:
            phone = str(phone)
            user = User.objects.filter(phone__iexact=phone)
            if user.exists():
                return Response({'status': False, 'detail': 'Phone Number already have account associated. Kindly try forgot password'})
            else:
                old = PhoneOTP.objects.filter(phone__iexact=phone)
                if old.exists():
                    old = old.first()
                    if old.logged:
                        Temp_data = {'phone': phone, 'password': password}

                        serializer = CreateUserSerializer(data=Temp_data)
                        serializer.is_valid(raise_exception=True)
                        user = serializer.save()
                        user.save()

                        old.delete()
                        return Response({
                            'status': True,
                            'detail': 'Congrts, user has been created successfully.'
                        })

                    else:
                        return Response({
                            'status': False,
                            'detail': 'Your otp was not verified earlier. Please go back and verify otp'

                        })
                else:
                    return Response({
                        'status': False,
                        'detail': 'Phone number not recognised. Kindly request a new otp with this number'
                    })

        else:
            return Response({
                'status': 'False',
                'detail': 'Either phone or password was not recieved in Post request'
            })


class ValidateOTP(APIView):
    '''
    If you have received otp, post a request with phone and that otp and you will be redirected to set the password
    '''

    def post(self, request, *args, **kwargs):
        phone = request.data.get('phone', False)
        otp_sent = request.data.get('otp', False)

        print(phone)
        print(otp_sent)
        if phone and otp_sent:
            old = PhoneOTP.objects.filter(phone__iexact=phone)
            if old.exists():
                old = old.first()
                otp = old.otp
                if str(otp) == str(otp_sent):
                    old.logged = True
                    old.save()
                    print("otp matched")
                    return Response({
                        'status': True,
                        'detail': 'OTP matched, kindly proceed to save password'
                    })
                else:
                    return Response({
                        'status': False,
                        'detail': 'OTP incorrect, please try again'
                    })
            else:
                return Response({
                    'status': False,
                    'detail': 'Phone not recognised. Kindly request a new otp with this number'
                })

        else:
            return Response({
                'status': 'False',
                'detail': 'Either phone or otp was not recieved in Post request'
            })


class ValidatePhoneSendOTP(APIView):
    '''
    This class view takes phone number and if it doesn't exists already then it sends otp for
    first coming phone numbers'''

    def post(self, request, *args, **kwargs):
        phone_number = request.data.get('phone')
        if phone_number:
            phone = str(phone_number)
            user = User.objects.filter(phone__iexact=phone)
            if user.exists():
                return Response({'status': False, 'detail': 'Phone Number already exists'})
                # logic to send the otp and store the phone number and that otp in table.
            else:
                otp = send_otp(phone)
                print(phone, otp)
                if otp:
                    otp = str(otp)
                    count = 0
                    old = PhoneOTP.objects.filter(phone__iexact=phone)
                    if old.exists():
                        count = old.first().count
                        old.update(count=count + 1)
                        old.first().save()
                        old.update(otp=otp)
                    else:
                        count = count + 1

                        PhoneOTP.objects.create(
                            phone=phone,
                            otp=otp,
                            count=count

                        )
                    if count > 7:
                        return Response({
                            'status': False,
                            'detail': 'Maximum otp limits reached. Kindly support our customer care or try with different number'
                        })

                else:
                    return Response({
                        'status': 'False', 'detail': "OTP sending error. Please try after some time."
                    })

                return Response({
                    'status': True, 'detail': 'Otp has been sent successfully.'
                })
        else:
            return Response({
                'status': 'False', 'detail': "I haven't received any phone number. Please do a POST request."
            })


def send_otp(phone):
    """
    This is an helper function to send otp to session stored phones or 
    passed phone number as argument.
    """

    if phone:

        key = random.randint(1000, 9999)
        phone = str(phone)
        otp_key = str(key)

        #link = f'https://2factor.in/API/R1/?module=TRANS_SMS&apikey=fc9e5177-b3e7-11e8-a895-0200cd936042&to={phone}&from=wisfrg&templatename=wisfrags&var1={otp_key}'

        #result = requests.get(link, verify=False)

        return otp_key
    else:
        return False


def send_otp_forgot(phone):
    if phone:
        key = random.randint(1000, 9999)
        phone = str(phone)
        otp_key = str(key)
        user = get_object_or_404(User, phone__iexact=phone)
        if user.name:
            name = user.name
        else:
            name = phone
        return otp_key
    else:
        return False

@api_view(['GET', ])
def MainServicesList(request):
    try:
        allServices = M_Services.objects.all().order_by('id')[:8]
    except M_Services.DoesNotExist:
        return Response(status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        serializer = M_ServicesSerializer(allServices, many=True)
        return Response(serializer.data)
        
@api_view(['GET', ])
def allServicesList(request):
    try:
        allServices = M_Services.objects.all()
    except M_Services.DoesNotExist:
        return Response(status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        serializer = M_ServicesSerializer(allServices, many=True)
        return Response(serializer.data)

@api_view(['GET', ])
def allSlidercards(request):
    try:
        sim = SliderImageModel.objects.all()
    except SliderImageModel.DoesNotExist:
        return Response(status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        serializer = SliderImageModelSerializer(sim, many=True)
        return Response(serializer.data)


@api_view(['GET', ])
def serviceOrList(request, service):
    try:
        ActiveService = M_Services.objects.get(pk=service)
        SubServices = M_SubServices.objects.filter(MainService=ActiveService)
    except M_Services.DoesNotExist or M_SubServices.DoesNotExist:
        return Response(status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        serializer = M_ServicesSerializer(SubServices, many=True)
        return Response(serializer.data)


@api_view(['GET', ])
def SubServiceView(request, service):
    print("Entering SubServiceView" + service)
    try:
        SubServicesm = M_SubServices.objects.get(pk=service)
    except M_SubServices.DoesNotExist:
        return Response(status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        serializer = M_SubServicesSerializer(SubServicesm, many=False)
        return Response(serializer.data)

@api_view(['GET', ])
def allRequests(request):
    try:
        SubServicesm = R_Requests.objects.all()
    except R_Requests.DoesNotExist:
        return Response(status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        serializer = R_RequestsSerializer(SubServicesm, many=True)
        return Response(serializer.data)


@api_view(['POST', ])
def RV_requests(request):
    ServiceID= request.data.get('ServiceID',False)
    UserId= request.data.get('UserId',False)
    Contact= request.data.get('Contact',False)
    Address= request.data.get('Address',False)
    Comments= request.data.get('Comments',False)
    Temp_data = {'ServiceID': ServiceID, 'UserId': UserId,'Contact':Contact,'Address':Address,'Comments':Comments,'Status':'Active'}
    serializer = R_RequestsSerializer(data=Temp_data)
    serializer.is_valid(raise_exception=True)
    check = serializer.save()
    if check :
        return Response({
            'status': True,
            'detail': 'Service Request posted.'
        })
    else:
        return Response({
            'status': False,
            'detail': 'Something went wrong, Please try again'
        })

@api_view(['GET', ])
def getUserRequests(request):
    try:
        userequests = R_Requests.objects.filter(UserId=User.objects.get(pk=request.user.id))
    except R_Requests.DoesNotExist:
        return Response(status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        serializer = R_RequestsSSerializer(userequests, many=True)
        return Response(serializer.data)
