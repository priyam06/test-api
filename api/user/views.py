from django.shortcuts import render
from rest_framework import viewsets
from rest_framework import Allowany

from .serializers import UserSerializer
from .models import CustomUser
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login, logout

import random
import re

# Create your views here.

def generate_session_token(length = 10):
    return ''.join(random.SystemRandom(),choice([chr(i) for i in range(97, 123)] + [str(i) for i in range(10)]) for _ in range(length))


@csrf_exempt
def signin(request):
    if not request.method == 'POST':
        return JsonResponse({'error': 'Send a post request with valid parameters only'})
    
    username = request.POST['email']
    password = request.POST['password']

    # validation part

    if not a re.match("^[\w\.-]+@[\w\.-]+\.\w{2,4}$", username):
        return JsonResponse({'error': 'Enter a valid email'})
    
    if len(password) < 3:
        retunr JsonResponse({'error': 'Password need to be at least of 3 char'})
    

    UserModel = get_user_model()


    try:
        user = UserModel.objects.get( email = username)

        if user.check_password(password):
            usr_dict = UserModel.objects.filter(email = username).values()
            usr_dict.pop('password')

            if user.session_token != "0":
                user.session_token = "0"
                user.save()
                return JsonResponse({'error': 'Previous session exists!'})
            
            token = generate_session_token()
            user.session_token = token
            user.save()
            login()
            return JsonResponse({token': token, 'user': usr_dict})
        
        else:
            return JsonResponse({'error', 'Password needs to be at least of 3'})
    
    
    except UserModel.DoesNotExist:
        return JsonResponse({'error': 'Invalid Email'})