from django.shortcuts import render
import calendar
from datetime import datetime
from django.contrib.auth.decorators import login_required , permission_required
from pypi_simple import PyPISimple 
from cloudsec.forms import Library_Form , CVE_Scan_Form
from cloudsec.models import  Library
from django.contrib import messages
from django.utils import timezone
from django.urls import reverse
from django.http import HttpResponseRedirect
import vulners  
from django.core.mail import send_mail


@login_required
def cloudsec_index(request):
    form = None
    url = "cloudsec/index.html" 
    if request.method == 'POST':
        form = Library_Form(request.POST, request.FILES)
        if(form.is_valid()):
            data = form.save(commit=False)
            data.created_at = timezone.now()
            data.updated_at = timezone.now()
            data.created_by = request.user.id
            data.save()
            messages.add_message(request, messages.INFO, 'Application Libraries stored successful')
            return HttpResponseRedirect(reverse('cloudsec:libraries'))
     
    else:
        form = Library_Form()
    
    context = {
        
        'title': "Add Requirement File",
        'form':form
        
    } 
     
    return render(request , url , context)

@login_required
def cloudsec_libraries(request):
    libraries = Library.objects.all().order_by('-id')
    url = "cloudsec/list_librabries.html" 
    # send_mail(
    #     'Payment',
    #     'find payment.',
    #     'kidkudzy@gmail.com',
    #     ['kmakufa@outlook.com', 'promiseksystems@gmail.com'],
    #     fail_silently=False,
    # )
    context = {
        
        'title': "Add Libraries",
        'libraries':libraries
        
    } 


    return render(request , url , context)



# @login_required
# def library_scan(request ,lib_id=None):
#     library = Library.objects.filter(id=lib_id).order_by('-id')
#     f = open(library[0].library_list.path, "r")
#     print("------------------")

#     lines = f.readlines()
#     for line in lines:
#         print(line)
#     print("------------------")
#     f.close()
#     context = {
#         "item":library[0], 
#         "lines":lines
#     }
#     return render(request, 'cloudsec/library_view.html', context)
    


@login_required
def library_scan(request ,lib_id=None):
    library = Library.objects.filter(id=lib_id).order_by('-id')
    f = open(library[0].library_list.path, "r")
    print("------------------")

    lines = f.readlines()
    for line in lines:
        print(line)
    print("------------------")
    f.close()
    context = {
        "item":library[0], 
        "lines":lines
    }

    
    return render(request, 'cloudsec/library_view.html', context)
    
@login_required
def query_db(request ,lib_id=None):
    library = Library.objects.filter(id=lib_id).order_by('-id')
    f = open(library[0].library_list.path, "r")
    print("------------------")

    lines = f.readlines()

    data = []
    count =0
    org_score = 0
    Issues = []
    Affected_Cve = []
    url_path = ""
   
    for line in lines:
        # here comes the vuln scanner logic
        sep = '=='
        stripped = line.split(sep, 1)[0]
        lib_version = line.split(sep, 1)[1]
        is_safe = False
        
        # print(line.strip())
        # print("-------without end-------")
        # print(line.split(sep, 1)[0])
        # print("------with end-----")
      
        # check updates and security
        with PyPISimple() as client:
            requests_page = client.get_project_page(stripped.strip())
        
        requests_page = client.get_project_page(stripped.strip())
        pkg_params = {}

        if(library[0].data_mode == 'application'):
            url_path = "cloudsec/app_cloudsec.html"
            
            try:
                try:
                    vulners_api = vulners.Vulners(api_key="4QIYDKA0NXPHUWXJNQYLISIZEZZH8FM25YNK0L518VOWJJEOWO81XGMH2KSL81KJ")
                    results = vulners_api.softwareVulnerabilities(stripped.strip(), lib_version.strip())
                    # print(len(stripped.strip()))
                    # print(len(lib_version.strip()))
                    # results = vulners_api.softwareVulnerabilities("httpd", "1.3")
                    exploit_list = results.get('exploit')
                    vulnerabilities_list = [results.get(key) for key in results if key not in ['info', 'blog', 'bugbounty']]
                    print("vulneralibity type_____"+vulnerabilities_list[0][0]['type'])
                    print(vulnerabilities_list[0][0]['title'])
                    Issues = vulnerabilities_list[0][0]
                    

                except:
                    is_safe = True
                    print("safe")
                pkg = requests_page.packages[0]
                pkg_params = {"name":pkg.project , "current_version":lib_version.strip() , "latest_version":pkg.version ,"digest":pkg.get_digests()['sha256'] , 'url':pkg.url ,'is_signed':pkg.has_sig ,'is_safe':is_safe ,'issue_title':Issues}
            except:
                pkg_params = {"name":stripped.strip() , "current_version":lib_version.strip() , "latest_version":"n/a" ,"digest":"n/a",'is_safe':is_safe ,'issue_title':Issues}

             # scan safety-db
            
            print("------check below-1-----------")
            # append scores and count 
            print()
            try:
                if isinstance(Issues['cvss']['score'], float):
                    org_score = org_score + Issues['cvss']['score']
                else:
                    print("not numeric")
            except:
                print("no score")
            count = count + 1


            print("------check below-2-----------")
            # print(pkg_params['issue_title']['cvss']['score'])

        
       

        data.append(pkg_params.copy())
    
        
           
    print(str(org_score)+"  "+str(count))
    print("------------------")
    f.close()
    context = {
        "item":library[0],
        "data":data ,
        'score':org_score / count , 
        'count':count ,
        'org_score':org_score ,
       
    }
    return render(request, url_path, context)
@login_required
def delete_librabry(request ,librabry_id=None):
    library = Library.objects.get(pk=librabry_id)
    library.delete()
    messages.add_message(request, messages.INFO, 'Library deleted')
    return HttpResponseRedirect('/cloudsec/files')


@login_required
def cve_scan(request):
    form = None
    url = "cloudsec/view_by_cve.html" 
    cve_data = []
    if request.method == 'POST':
        url = "cloudsec/cve_results.html"
        form = CVE_Scan_Form(request.POST)
        if(form.is_valid()):
           
            data = form.cleaned_data['cve_name']
            print("^^^^^^^^^^^")

            vulners_api = vulners.Vulners(api_key="4QIYDKA0NXPHUWXJNQYLISIZEZZH8FM25YNK0L518VOWJJEOWO81XGMH2KSL81KJ")
            cve_data = vulners_api.document(data)
            print(cve_data)
        
     
    else:
        form = CVE_Scan_Form()
    
    context = {
        
        'title': "Scan by Cve",
        'form':form,
        'cve_data':cve_data
        
    } 
     
    return render(request , url , context)