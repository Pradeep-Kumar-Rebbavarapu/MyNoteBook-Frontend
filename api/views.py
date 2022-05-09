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
def home(request):
    return HttpResponse('hello')

#signup
class Signup(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    
    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data["refresh"] = str(refresh)   # comment out if you don't want this
        data["access"] = str(refresh.access_token)
        data["email"] = self.user.email
        data["username"] = self.user.username
        """ Add extra responses here should you wish
        data["userid"] = self.user.id
        data["my_favourite_bird"] = "Jack Snipe"
        """
        return data


class MyObtainTokenPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer
    
    def post(self, request, *args, **kwargs):
        # you need to instantiate the serializer with the request data
        serializer = self.serializer_class(data=request.data)
        # you must call .is_valid() before accessing validated_data
        serializer.is_valid(raise_exception=True)  

        # get access and refresh tokens to do what you like with
        access = serializer.validated_data.get("access", None)
        refresh = serializer.validated_data.get("refresh", None)
        email = serializer.validated_data.get("email", None)
        username = serializer.validated_data.get("username", None)
        print(access)

        # build your response and set cookie
        if access is not None:
            response = Response({"access": access, "refresh": refresh, "email": email,"username":username}, status=200)
            response.set_cookie('token', access, httponly=True,samesite=False, secure=True)
            response.set_cookie('refresh', refresh, httponly=True,samesite=False, secure=True)
            response.set_cookie('email', email, httponly=True,samesite=False, secure=True)
            response.set_cookie('username',username, httponly=True,samesite=False, secure=True)
            return response

        return Response({"Error": "Something went wrong"},statuc=status.HTTP_400_BAD_REQUEST)

class Login(APIView):
    def post(self,request):
        username = request.data['username']
        password = request.data['password']
        email = request.data['email']
        response = Response()
        # checking for errors
        user = User.objects.filter(username=username).first()
        print(user)
        if user is None:
                    return Response({'error': 'invalid username or password'}, status=status.HTTP_404_NOT_FOUND)
        if not user.check_password(password):
                    return Response({'error': 'invalid username or password'},status=status.HTTP_404_NOT_FOUND)
        else:
            if email == user.email:
                    refresh = RefreshToken.for_user(user)
                    print('access token',str(refresh.access_token))
                    response.set_cookie('accesstoken',str(refresh.access_token))
                    response.set_cookie('refreshtoken',str(refresh))
                    return Response({
                        'refresh': str(refresh),
                        'access': str(refresh.access_token)},
                        status=status.HTTP_200_OK)
            else:
                return Response({'errors':'email not matched'},status=status.HTTP_404_NOT_FOUND)

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


        
