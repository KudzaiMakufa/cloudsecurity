from django.urls import path
from cloudsec import views
app_name = 'cloudsec'
urlpatterns = [ 
    path('create', views.cloudsec_index ,name="index"),
    path('files', views.cloudsec_libraries ,name="libraries"),
    path('scan/<int:lib_id>', views.library_scan , name="lib_scan"),
    path('check/<int:lib_id>', views.query_db , name="vuln_check"),
    path('delete_librabry/<int:librabry_id>', views.delete_librabry , name="delete_librabry"),
    path('cve_scan', views.cve_scan , name="cve_scan"),
    # path('scan_all', views.scan_all , name="scan_all"),


    
 
]