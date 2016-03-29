from __future__ import unicode_literals

from django.db import models
from django import forms

# Create your models here.

class LoginPromptForm(forms.Form):
    username = forms.CharField(max_length=20)
    password = forms.CharField(max_length=20)

class KeyResponseForm(forms.Form):
    response = forms.CharField()
