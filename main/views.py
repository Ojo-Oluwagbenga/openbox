from django.shortcuts import render
from django.shortcuts import redirect

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import os
from .models import Task_Notice, Task


# Create your views here.

def only_logged_outs(v_method):
    def wrap(response):
        if response.session.get("user_data"):
            return redirect("/dashboard")
        else:
            return v_method(response)
    return wrap

@only_logged_outs
def login(response):
    return render(response, "login.html", {})


def dashboard(response):
    if not response.session.get("user_data"):
        response.session.flush()
        return redirect("/login")
            
    #UPDATE THE USER KEY EXPIRY SINCE USER IS ACTIVE
    response.session.set_expiry(864000) #SHIFTS TO 10 DAYS FROM NOW
    
    qset = {
        "user_data":response.session['user_data'],
        "name":response.session['user_data']['user_name']
    }

    return render(response, "dashboard.html", qset)

def homepage(response):
    return render(response, "homepage.html", {})

def report(response, report_code):
    if not response.session.get("user_data"):
        response.session.flush()
        return redirect("/login")
            
    #UPDATE THE USER KEY EXPIRY SINCE USER IS ACTIVE
    response.session.set_expiry(864000) #SHIFTS TO 10 DAYS FROM NOW
    user_code = response.session['user_data'].get("user_code")
    
    qset = {
        'draft':"Here is the draft",
        'login_type':'-'
    }

    return render(response, "report.html", qset)


def logout(response):
    response.session.flush()
    return redirect("/login")

def bluetest(response):
    return render(response, "bluetest.html", {})

def uploadboxes(response):
    return render(response, "uploadboxes.html", {})

def get_box_notice(response):
    print ("Got here")
    box_code = response.GET.get('box_code')
    upd_code = response.GET.get('upd_code')

    print (upd_code)
    print (box_code)

    notices = Task_Notice.objects.filter(box_code=box_code)
    print(notices)
    if (not notices):
        print("box unfound")
        return JsonResponse({'has_job': False})
    notice = notices[0]
    if not notice.has_job:
        print("box found")
        return JsonResponse({'has_job': False})
    if str(notice.upd_code) == str(upd_code):
        tasks = Task.objects.filter(task_code__in=notice.task_codes)
        for tk in tasks:
            tk.status = "completed"
            tk.save()

        notice.delete()
        return JsonResponse({'has_job': False})
         
    return JsonResponse({
        'has_job': True,
        "task_codes":notice.task_codes,
        'upd_code':notice.upd_code
    })

def check_task_status(response):
    task_code = response.GET.get('task_code')
    tasks = Task.objects.filter(task_code=task_code)
    if (not tasks):
        print("task unfound")
        return JsonResponse({'status': "Task does not exist"})
    task = tasks[0]
    durl = ""
    task_type = task.package_data['package_type']
    if task_type == "print_doc":
        durl = task.package_data["document_source_url"]
    return JsonResponse({
        'status': task.status,
        'time_started':task.time_in,
        'time_completed':task.time_completed,
        'doc_url':durl, 
        "task_type": task_type
    })

def error_view(response):
    return render(response, "error_view.html", {})

# @csrf_exempt  # For development only; use CSRF tokens in production
def upload_document(request):
    if request.method == 'POST' and request.FILES.get('document'):
        uploaded_file = request.FILES['document']
        upload_dir = os.path.join(settings.MEDIA_ROOT, 'uploaded')
        os.makedirs(upload_dir, exist_ok=True)  # ✅ Create the directory if missing

        file_path = os.path.join(upload_dir, uploaded_file.name)

        with open(file_path, 'wb+') as dest:
            for chunk in uploaded_file.chunks():
                dest.write(chunk)
        # with open(f'media/uploaded/{uploaded_file.name}', 'wb+') as destination:
        #     for chunk in uploaded_file.chunks():
        #         destination.write(chunk)
        return JsonResponse({'message': 'Upload successful'})
    return JsonResponse({'error': 'Invalid request'}, status=400)
