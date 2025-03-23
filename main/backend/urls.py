from django.urls import path
from . import apimanager

urlpatterns = [
    path('<str:apiclass>/<str:apimethod>', apimanager.Manager.manager, name='manager')

]