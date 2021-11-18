# from django.contrib import admin
from django.urls import path
from . import views
urlpatterns = [
    # path('admin/', admin.site.urls),
    path('signup/', views.sign_up, name='signup'),
    path('', views.user_login, name='login'),
    path('home/', views.home, name='home'),
    path('show/', views.show, name='show'),
    path('adduser/', views.Adduser, name='adduser'),
    path('profile/', views.user_profile, name='profile'),
    path('logout/', views.user_logout, name='logout'),
    path('update/<int:id1>/', views.update_record, name='update'),
    path('delete/<int:id1>/', views.delete, name='delete'),
    path("password_reset", views.password_reset_request, name="password_reset"),
    path("changepass/", views.user_change_pass, name="password_reset"),
]