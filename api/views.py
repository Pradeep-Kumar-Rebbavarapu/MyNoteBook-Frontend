from ast import Pass
from xmlrpc.client import ResponseError
from django.http import HttpResponse
from django.shortcuts import render
from rest_framework.decorators import *
from .serializers import *
from rest_framework.response import Response
from rest_framework.decorators import *
from rest_framework import status
from .models import *
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView  
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import *
# Create your views here.
import jwt
import datetime
from django.views.decorators.csrf import csrf_exempt 
import json
from django.http import JsonResponse
from rest_framework.renderers import JSONRenderer

from rest_framework.generics import *
from django.contrib.auth.models import User
# Create your views here
from rest_framework.filters import SearchFilter
#signup user
import json
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import authenticate
from backend import settings
from django.middleware import csrf
def home(request):
    return HttpResponse('hello')

#signup
class Signup(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class LoginView(APIView):
    def post(self, request, format=None):
        data = request.data
        response = Response()        
        username = data.get('username', None)
        password = data.get('password', None)
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                data = get_tokens_for_user(user)
                response.set_cookie(
                    key = settings.SIMPLE_JWT['AUTH_COOKIE'], 
                    value = data["access"],
                    expires = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                    secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                    httponly = settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                    samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                )
                csrf.get_token(request)
                response.data = {"Success" : "Login successfully","data":data}
                return response
            else:
                return Response({"No active" : "This account is not active!!"}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({"Invalid" : "Invalid username or password!!"}, status=status.HTTP_404_NOT_FOUND)

class getUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self,request):
        user=request.user
        print(user)
        payload = {
            'id':user.id,
            'username':user.username,
            'email':user.email,
            'first_name':user.first_name,
            'last_name':user.last_name,
        }
        return Response({'status':"success",'payload':payload})





#notes section



# adding notes
class AddNote(CreateAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    queryset=Note.objects.all()
    serializer_class = NoteSerializer

class GetUserNotes(ListAPIView):
    filter_backends = [SearchFilter]
    search_fields = ['title','desc']
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        user_id=user.id
        authtoken = self.request.auth
        print(authtoken)
        queryset = Note.objects.filter(user=1)
        return queryset
    def get_serializer_class(self):
        serializer_class = NoteSerializer
        return serializer_class


        

class DeleteNote(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def delete(self,request,pk):
        user=request.user
        user_id = user.id
        allnotes = Note.objects.get(note_id=pk)
        print(allnotes.user)
        if allnotes.user == user:
            allnotes.delete()
            return Response('deleted succesfully')
        else:
            return Response('unauthorised')

class UpdateNote(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def patch(self,request,pk):
        data=request.data
        user = request.user
        allnotes = Note.objects.get(note_id=pk)
        serializer = NoteSerializer(allnotes,data=data,partial=True)
        if allnotes.user == user:
            if serializer.is_valid():
                serializer.save()
                return Response('Updated  succesfully')
            else:
                return Response(serializer.errors)
        else:
            return Response('unauthorised')


        
