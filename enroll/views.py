import datetime
from django.shortcuts import render, HttpResponseRedirect
from .forms import SignUpForm, EditUserProfileForm
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm, SetPasswordForm
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from .forms import DetailsForm
from django.contrib.auth.models import User
from . forms import Add_User
from django.shortcuts import render, redirect
from django.core.mail import send_mail, BadHeaderError
from django.http import HttpResponse
from django.contrib.auth.forms import PasswordResetForm
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes


# Signup View Function
def sign_up(request):
  # fm = SignUpForm()
 if request.method == "POST":
  fm = SignUpForm(request.POST)
  if fm.is_valid():
   messages.success(request, 'Account Created Successfully !!') 
   fm.save()
 else:
  fm = SignUpForm()
 return render(request, 'enroll/signup.html', {'form':fm})

# Login View Function
def user_login(request):
  if not request.user.is_authenticated:
    if request.method == "POST":
      fm = AuthenticationForm(request=request, data=request.POST)
      if fm.is_valid():
        uname = fm.cleaned_data['username']
        upass = fm.cleaned_data['password']
        user = authenticate(username=uname, password=upass)
        if user is not None:
          login(request, user)
          if user.is_superuser:

              messages.success(request, '(admin)Logged in successfully !!')
              return HttpResponseRedirect('/home/')
          else:
              messages.success(request, '(User)Logged in successfully !!')
              return HttpResponseRedirect('/profile/')

    else: 
      fm = AuthenticationForm()
    return render(request, 'enroll/userlogin.html', {'form':fm})
  else:
    return HttpResponseRedirect('/home/')

# Profile
def user_profile(request):
  if request.user.is_authenticated:
    if request.method == "POST":
      fm = EditUserProfileForm(request.POST, instance=request.user)
      if fm.is_valid():
        messages.success(request, 'Profile Updated !!!')
        fm.save()
    else:
      fm = EditUserProfileForm(instance=request.user)
    return render(request, 'enroll/profile.html', {'name': request.user, 'form':fm})
  else:
    return HttpResponseRedirect('/')

# Logout
def user_logout(request):
  logout(request)
  return HttpResponseRedirect('/')

# Change Password with old Password
def user_change_pass(request):
  if request.user.is_authenticated:
    if request.method == "POST":
      fm = PasswordChangeForm(user=request.user, data=request.POST)
      if fm.is_valid():
        fm.save()
        update_session_auth_hash(request, fm.user)
        messages.success(request, 'Password Changed Successfully')
        return HttpResponseRedirect('/profile/')
    else:
      fm = PasswordChangeForm(user=request.user)
    return render(request, 'enroll/changepass.html', {'form':fm})
  else:
    return HttpResponseRedirect('/login/')

def home(request):
  if request.method =='GET':
    return render(request,'enroll/home.html')

def show(request):
  emp1 = DetailsForm()
  emp = User.objects.all()
  di = {'emp': emp, 'emp1': emp1}
  return render(request, 'enroll/details.html', context=di)

def update_record(request, id1):
    if request.user.is_authenticated:
        if request.method == "POST":
            fm = EditUserProfileForm(request.POST, instance=request.user)
            if fm.is_valid():
                messages.success(request, 'Profile Updated !!!')
                fm.save()
                return HttpResponseRedirect('/show/')
        else:
            fm = EditUserProfileForm(instance=request.user)
        return render(request, 'enroll/update.html', {'name': request.user, 'form': fm})
    else:
        return HttpResponseRedirect('/')


# emp = User.objects.get(id=id1)
  # di = {'emp': emp}
  # if request.method == 'POST':
  #   emp = DetailsForm(request.POST)
  #   if emp.is_valid():
  #     emp.save(commit='true')
  #     return redirect('/show/')
  # return render(request, 'enroll/update.html',context=di)

def delete(request, id1):
  emp = User.objects.get(id=id1)
  emp.delete()
  return HttpResponseRedirect('/show/')


def Adduser(request):
    # fm = SignUpForm()
    if request.method == "POST":
        fm = Add_User(request.POST)
        if fm.is_valid():
            messages.success(request, 'Account Created Successfully !!')
            fm.save()
            return HttpResponseRedirect('/adduser/')
    else:
        fm = Add_User()
    return render(request, 'enroll/adduser.html', {'form': fm})


def password_reset_request(request):
    if request.method == "POST":
        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            associated_users = User.objects.filter(Q(email=data))
            if associated_users.exists():
                for user in associated_users:
                    subject = "Password Reset Requested"
                    email_template_name = "enroll/password/password_reset_email.txt"
                    c = {
                        "email": user.email,
                        'domain': '127.0.0.1:8000',
                        'site_name': 'Website',
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        send_mail(subject, email, 'prashant.sahu446@gmail.com', [user.email], fail_silently=False)
                    except BadHeaderError:
                        return HttpResponse('Invalid header found.')
                    return redirect("/password_reset/done/")
    password_reset_form = PasswordResetForm()
    return render(request=request, template_name="enroll/password/password_reset.html",
                  context={"password_reset_form": password_reset_form})
