from django.urls import path
from . import views

urlpatterns = [    
    path("login", views.login, name="login"),
    
    path("dashboard", views.dashboard, name="signup"),
    path("report/<str:report_code>", views.report, name="report"),

    path("logout", views.logout, name="signup"),
    path("", views.homepage, name="homepage"),

]