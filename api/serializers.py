from cProfile import label
from re import L
from rest_framework import serializers
from django.contrib.auth import get_user_model

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
import uuid
from django.conf import settings
from django.contrib.auth.models import User

from .models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email','username','password')
    def create(self, data):
        user = User.objects.create(
            email=data.get('email'),
            password = data.get('password'),
            username=data.get('username')
            )
        user.set_password(data.get('password'))
        user.save()
        return user
    def validate(seld,data):
        user_email = User.objects.filter(email=data.get('email')).exists()
        if user_email:
            raise serializers.ValidationError({'error':'Email Already Exists Try With Another'})
        else:
            return data
class NoteSerializer(serializers.ModelSerializer):
        
    class Meta:
        model=Note
        fields="__all__"
    def create(self,data):
        def getdate():
            today = date.today()
            day = today.day
            mydate = datetime.datetime.now()
            month = mydate.strftime("%B")
            year = today.year
            if day == 1 or day == 21 or day == 31:
                current_day = f"{day}st {month} {year}"
                
            else:
                current_day = f"{day}th {month} {year}"
            return current_day
        def gettime():
            now = datetime.datetime.now()
            current_time = now.strftime("%H:%M:%S")
            if int(current_time[0:2]) > 12:
                current_time = str((int(current_time[0:2])-12))    +current_time[2:] + ' pm'
            elif int(current_time[0:2]) == 12:
                current_time = str(current_time[0:2]) +     current_time[2:] + ' pm'
            elif int(current_time[0:2]) == 24:
                current_time = str((int(current_time[0:2])-12))    +current_time[2:] + ' am'
            else:
                current_time = str(current_time) + ' am'
            return current_time
        note = Note.objects.create(title=data.get('title'),user=data.get('user'),tag=data.get('tag'),desc=data.get('desc'),datestamp=getdate(),timestamp=gettime())
        note.save()
        return note