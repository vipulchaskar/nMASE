from django.conf.urls import patterns, url

from engine import views

urlpatterns = patterns('',
    url(r'^epra_ip', views.epra_ip, name='epra_ip'),
    url(r'^fileup', views.fileup, name='fileup'),
    url(r'^homepage', views.homepage, name='homepage'),
    url(r'^results', views.homepage, name='homepage'),
    url(r'^packetview',views.three,name='three'),
    url(r'^', views.homepage, name='homepage'),
    url(r'^homepage', views.homepage, name='index'),

)
