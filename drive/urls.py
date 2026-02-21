from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('files/', views.files_view, name='files'),
    path('upload/', views.upload_file, name='upload_file'),
    path('download/<str:file_id>/', views.download_file, name='download_file'),
    path('delete-file/<str:file_id>/', views.delete_file, name='delete_file'),
    path('search/', views.search_view, name='search'),
    path('api/search/', views.search_api, name='search_api'),
    path('records/', views.records_view, name='records'),
    path('records/upload/', views.upload_record, name='upload_record'),
    path('records/delete/<str:record_id>/', views.delete_record, name='delete_record'),
    path('records/view/<str:record_id>/', views.view_record, name='view_record'),
    path('visualizer/', views.visualizer_view, name='visualizer'),
    path('api/visualizer/', views.visualizer_api, name='visualizer_api'),
    path('analytics/', views.analytics_view, name='analytics'),
]
