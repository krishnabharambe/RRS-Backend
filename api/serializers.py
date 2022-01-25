from dataclasses import fields
from operator import mod
from rest_framework import serializers
from django.contrib.auth import authenticate

from django.contrib.auth import get_user_model
User = get_user_model()

from .models import SliderImageModel, M_Services, M_SubServices, R_Requests, Profile, RequestAssign



class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields='__all__'

class R_RequestsSerializer(serializers.ModelSerializer):
    class Meta:
        model = R_Requests
        fields = '__all__'

class M_ServicesSerializer(serializers.ModelSerializer):
    class Meta:
        model = M_Services
        fields = ['id', 'title', 'description',
                  'shortdescription', 'status', 'icon', 'uploaded_at']

class M_SubServicesSerializer(serializers.ModelSerializer):
    class Meta:
        model = M_SubServices
        fields = '__all__'

class RequestAssignSerializer(serializers.ModelSerializer):
    booking = R_RequestsSerializer(read_only=True)
    class Meta:
        model = RequestAssign
        fields='__all__'

class M_Services4Serializer(serializers.ModelSerializer):
    subs = M_SubServicesSerializer(read_only=True)
    class Meta:
        model = M_Services
        fields = ['id', 'title', 'description',
                  'shortdescription', 'status', 'icon', 'uploaded_at','subs']

# class M_SubServices4Serializer(serializers.ModelSerializer):
#     MainService = M_ServicesSerializer(read_only=True)
#     class Meta:
#         model = M_SubServices
#         fields = '__all__'

class R_RequestsSSerializer(serializers.ModelSerializer):
    ServiceID = M_SubServicesSerializer(read_only=True)
    class Meta:
        model = R_Requests
        fields = '__all__'

class SliderImageModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = SliderImageModel
        fields = '__all__'



class CreateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('phone', 'password')
        extra_kwargs = {'password': {'write_only': True}, }

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user


class CreateTechUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('phone', 'password')
        extra_kwargs = {'password': {'write_only': True}, }

    def create(self, validated_data):
        user = User.objects.create_staffuser(**validated_data)
        return user


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('id', 'phone', 'first_login')


class LoginUserSerializer(serializers.Serializer):
    phone = serializers.CharField()
    password = serializers.CharField(
        style={'input_type': 'password'}, trim_whitespace=False)

    def validate(self, attrs):
        phone = attrs.get('phone')
        password = attrs.get('password')

        if phone and password:
            if User.objects.filter(phone=phone).exists():
                user = authenticate(request=self.context.get('request'),
                                    phone=phone, password=password)
            else:
                msg = {'detail': 'Phone number is not registered.',
                       'register': False}
                raise serializers.ValidationError(msg)

            if not user:
                msg = {
                    'detail': 'Unable to log in with provided credentials.', 'register': True}
                raise serializers.ValidationError(msg, code='authorization')

        else:
            msg = 'Must include "username" and "password".'
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs

class LoginTechUserSerializer(serializers.Serializer):
    phone = serializers.CharField()
    password = serializers.CharField(
        style={'input_type': 'password'}, trim_whitespace=False)

    def validate(self, attrs):
        phone = attrs.get('phone')
        password = attrs.get('password')

        if phone and password:
            if User.objects.filter(phone=phone).exists():
                user = authenticate(request=self.context.get('request'),
                                    phone=phone, password=password)
            else:
                msg = {'detail': 'Phone number is not registered.',
                       'register': False}
                raise serializers.ValidationError(msg)

            if not user:
                msg = {
                    'detail': 'Unable to log in with provided credentials.', 'register': True}
                raise serializers.ValidationError(msg, code='authorization')

        else:
            msg = 'Must include "username" and "password".'
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs


class ChangePasswordSerializer(serializers.Serializer):
    """
    Used for both password change (Login required) and 
    password reset(No login required but otp required)
    not using modelserializer as this serializer will be used for for two apis
    """

    password_1 = serializers.CharField(required=True)
    # password_1 can be old password or new password
    password_2 = serializers.CharField(required=True)
    # password_2 can be new password or confirm password according to apiview


class ForgetPasswordSerializer(serializers.Serializer):
    """
    Used for resetting password who forget their password via otp varification
    """
    phone = serializers.CharField(required=True)
    password = serializers.CharField(required=True)