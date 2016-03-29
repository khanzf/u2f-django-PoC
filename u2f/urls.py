from django.conf.urls import patterns, url

from . import views

urlpatterns = [
    url(r'^login/', views.login, name='login'),
    url(r'^add_key/', views.add_key, name='add_key'),
    url(r'^twofactor/', views.twofactor, name='twofactor'),
]
