from django.contrib.auth.models import User
from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.core import validators


class SignUpForm(UserCreationForm):
 # password2 = forms.CharField(label='Confirm Password (again)', widget=forms.PasswordInput)

 class Meta:
  model = User
  fields = ['username', 'first_name', 'last_name', 'email', 'password1','password2']
  labels = {'email': 'Email','password2':'Confirm Password(again)'}

 # def clean(self):
 #  cleaned_data = super(SignUpForm, self).clean()
 #  username = cleaned_data.get('username')
 #  firsrname = cleaned_data.get('first_name')
 #
 #  if username != firsrname:
 #   raise forms.ValidationError('not match')


class EditUserProfileForm(UserChangeForm):
 password = None
 class Meta:
  model = User
  fields = ['username', 'first_name', 'last_name', 'email', 'date_joined', 'last_login', 'is_active']
  labels = {'email': 'Email'}

class DetailsForm(forms.ModelForm):
 password = None

 class Meta:
  model = User
  fields = ['username', 'first_name', 'last_name', 'email', 'date_joined', 'last_login', 'is_active']
  labels = {'email': 'Email'}

class Add_User(UserCreationForm):
 password2 = forms.CharField(label='Confirm Password (again)', widget=forms.PasswordInput)
 class Meta:
  model = User
  fields = ['username', 'first_name', 'last_name', 'email','password1']
  labels = {'email': 'Email'}
