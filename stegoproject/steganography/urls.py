from django.urls import path
from . import views

urlpatterns = [

    path('', views.home, name='home'),
    path('hide/', views.hide_data, name='hide_data'),
    path('download/', views.download_stego, name='download_stego'),
    path('decrypt/', views.decrypt_data, name='decrypt_data'),
]


