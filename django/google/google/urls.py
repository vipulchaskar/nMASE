from django.conf.urls import patterns, include, url
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from google import settings


urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'google.views.home', name='home'),
    url(r'^engine/', include('engine.urls'), name='engine'),
    url(r'^nmase/', include('engine.urls'), name='engine'),
    url(r'^admin/', include(admin.site.urls)),
    (r'^accounts/', include('registration.backends.simple.urls')),
)



