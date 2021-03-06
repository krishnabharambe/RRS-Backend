from django.db import models
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.validators import RegexValidator
from django.db.models import Q
from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
# from rest_framework.authtoken.models import Token
from django.db.models.signals import post_save
# Create your models here.
import random
import os


STATUS_CHOICES = (
    ('Active','Active'),
    ('Pending', 'Pending'),
    ('Complete','Complete'),
    ('Archived','Archived'),
    ('Cancelled','Cancelled'),
    ('OpenPool','OpenPool')
)

STATUS_CHOICES2 = (
    ('Active','Active'),
    ('Pending', 'Pending'),
    ('Complete','Complete'),
    ('Archived','Archived'),
    ('Cancelled','Cancelled'),
    ('OpenPool','OpenPool')
)

class UserManager(BaseUserManager):
    def create_user(self, phone, password=None, is_staff=False, is_active=True, is_admin=False):
        if not phone:
            raise ValueError('users must have a phone number')
        if not password:
            raise ValueError('user must have a password')

        user_obj = self.model(
            phone=phone
        )
        user_obj.set_password(password)
        user_obj.staff = is_staff
        user_obj.admin = is_admin
        user_obj.active = is_active
        user_obj.save(using=self._db)
        return user_obj

    def create_staffuser(self, phone, password=None):
        user = self.create_user(
            phone,
            password=password,
            is_staff=True,
        )
        return user

    def create_superuser(self, phone, password=None):
        user = self.create_user(
            phone,
            password=password,
            is_staff=True,
            is_admin=True,
        )
        return user



class User(AbstractBaseUser):
    phone_regex = RegexValidator( regex   =r'^\+?1?\d{9,14}$', message ="Phone number must be entered in the format: '+999999999'. Up to 14 digits allowed.")
    phone       = models.CharField(validators=[phone_regex], max_length=17, unique=True)
    name        = models.CharField(max_length = 256, blank = True, null = True)
    first_login = models.BooleanField(default=False)
    active      = models.BooleanField(default=True)
    staff       = models.BooleanField(default=False)
    admin       = models.BooleanField(default=False)
    timestamp   = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.phone

    def get_full_name(self):
        return self.name

    def get_short_name(self):
        return self.phone

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):

        return True

    @property
    def is_staff(self):
        return self.staff

    @property
    def is_admin(self):
        return self.admin

    @property
    def is_active(self):
        return self.active


def upload_image_path_profile(instance, filename):
    new_filename = random.randint(1,9996666666)
    name, ext = get_filename_ext(filename)
    final_filename = '{new_filename}{ext}'.format(new_filename=new_filename, ext=ext)
    return "profile/{new_filename}/{final_filename}".format(
            new_filename=new_filename,
            final_filename=final_filename
    )
         

def get_filename_ext(filepath):
    base_name = os.path.basename(filepath)
    name, ext = os.path.splitext(base_name)
    return name, ext


class Profile(models.Model):
    user            =   models.OneToOneField(User,related_name="usr", on_delete= models.CASCADE)
    email           =   models.EmailField( blank = True, null = True)
    image           =   models.ImageField(upload_to = upload_image_path_profile, default=None, null = True, blank = True)
    address         =   models.CharField(max_length = 900, blank = True, null = True)
    fullName         =   models.CharField(max_length = 900, blank = True, null = True)
    city            =   models.CharField(max_length = 30, blank = True, null = True)
    first_count     =   models.IntegerField(default=0, help_text='It is 0, if the user is totally new and 1 if the user has saved his standard once' )

    def __str__(self):
        return str(self.user) 



def user_created_receiver(sender, instance, created, *args, **kwargs):
    if created:
        Profile.objects.get_or_create(user = instance)
post_save.connect(user_created_receiver, sender = User)



class PhoneOTP(models.Model):
    phone_regex = RegexValidator( regex   =r'^\+?1?\d{9,14}$', message ="Phone number must be entered in the format: '+999999999'. Up to 14 digits allowed.")
    phone       = models.CharField(validators=[phone_regex], max_length=17, unique=True)
    otp         = models.CharField(max_length = 9, blank = True, null= True)
    count       = models.IntegerField(default = 0, help_text = 'Number of otp sent')
    logged      = models.BooleanField(default = False, help_text = 'If otp verification got successful')
    forgot      = models.BooleanField(default = False, help_text = 'only true for forgot password')
    forgot_logged = models.BooleanField(default = False, help_text = 'Only true if validdate otp forgot get successful')


    def __str__(self):
        return str(self.phone) + ' is sent ' + str(self.otp)



class SliderImageModel(models.Model):
    title = models.TextField(max_length=1000, default="Restore")
    image = models.ImageField(upload_to='SliderImages/', blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class M_Services(models.Model):
    title = models.CharField(max_length=1000)
    description = models.TextField()
    shortdescription = models.CharField(max_length=1000)
    status = models.CharField(max_length=1000)
    icon = models.ImageField(upload_to='images/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class M_SubServices(models.Model):
    MainService = models.ForeignKey(
    M_Services,related_name="mservice",on_delete=models.CASCADE)
    title = models.CharField(max_length=1000)
    description = models.TextField()
    shortdescription = models.CharField(max_length=1000)
    status = models.CharField(max_length=1000)
    icon = models.ImageField(upload_to='images/')
    TileImage = models.ImageField(upload_to='Tileimages/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

class R_Requests(models.Model):
    ServiceID = models.ForeignKey(M_SubServices, related_name="subservice", on_delete=models.CASCADE)
    UserId = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    Contact = models.CharField(max_length=1000)
    Address = models.TextField()
    Comments = models.TextField()
    Status = models.CharField(max_length=100, choices=STATUS_CHOICES2, default='Active')
    uploaded_at = models.DateTimeField(auto_now_add=True)

class Offers(models.Model):
    user = models.ForeignKey(User, on_delete= models.CASCADE)
    image = models.ImageField(upload_to = "Offers/", default=None, null = True, blank = True)
    OfferCode = models.CharField(max_length = 30, null = True)
    Status = models.CharField(max_length=100, choices=STATUS_CHOICES, default='Active')

    def __str__(self):
        return str(self.user) 


class RequestAssign(models.Model):
    user = models.ForeignKey(User, related_name="staffDetails",on_delete= models.CASCADE)
    booking = models.ForeignKey(R_Requests,related_name="bookingDetails", on_delete= models.CASCADE)
    bookingStatus = models.CharField(max_length=100, choices=STATUS_CHOICES, default='Active')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    