from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('login/google/', views.google_signin_start_view, name='google_signin_start'),
    path('post-auth/', views.post_auth_view, name='post_auth'),
    path('unlock/', views.unlock_data_view, name='unlock_data'),
    path('logout/', views.logout_view, name='logout'),
    path('2fa/setup/', views.setup_2fa_view, name='setup_2fa'),
    path('2fa/verify/', views.verify_2fa_view, name='verify_2fa'),
    path('2fa/recovery-codes/', views.recovery_codes_view, name='recovery_codes'),
    path('change-password/', views.change_password_view, name='change_password'),
]
