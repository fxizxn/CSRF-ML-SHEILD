"""CSRF URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from . import index
from django.conf import settings
from django.conf.urls.static import static



urlpatterns = [
    path('admin/', admin.site.urls), 
    path('page1',index.page1),
    path('aboutus',index.aboutus),
    path('register',index.register),
    path('ourteam',index.ourteam),
    path('contact',index.contact),
    path('',index.page1),
    path('doregister',index.doregister),
    path('malicious',index.malicious),
    path('dologin',index.dologin),
    path('viewuser',index.viewuser),
    path('logout',index.logout),
    path('temp',index.temp),
    path('userhome',index.userhome),
    path('adminhome',index.adminhome),
    path('doremove',index.doremove),
    path('viewpredicadmin',index.viewpredicadmin),
    path('csrfdetect',index.csrfdetect),
    path('csrfdetect1',index.csrfdetect1),
    path('csrfanalysis',index.csrfanalysis),
    path('readmore',index.readmore)

]+ static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)


