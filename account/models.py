
from django.db import models
import uuid
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
import pyotp

class UserManager(BaseUserManager):
    use_in_migrations = True
    def create_user(self, name, email, password=None):
        if not email:
            raise ValueError('Email address is required')

        user = self.model(
            email=self.normalize_email(email),
        )
        user.name = name
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.otp_key = pyotp.random_base32()
        while True:
            try:
                user.save(using=self._db)
                break
            except Exception as e:
                user.otp_key = pyotp.random_base32()
        return user

    def create_superuser(self, name, email, password):

        if password is None:
            raise TypeError('Superusers must have a password.')

        user = self.create_user(name,email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()

        return user

class User(AbstractBaseUser, PermissionsMixin):

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True
        )
    name = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    otp_key = models.CharField(max_length=100,blank=False,null=False,unique=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']


    objects = UserManager()

    def __str__(self):
        return self.email

    class Meta:
        db_table = "login"

