from django.urls import path
from . import views

urlpatterns = [    
    path("login", views.login, name="login"),
    path("bluetest", views.bluetest, name="login"),
    path('upload/', views.upload_document, name='upload_document'),
    
    path("dashboard", views.dashboard, name="signup"),
    path("report/<str:report_code>", views.report, name="report"),

    path("logout", views.logout, name="signup"),
    path("", views.homepage, name="homepage"),

]


