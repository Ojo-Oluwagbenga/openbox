from django.shortcuts import render
from django.shortcuts import redirect

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import os


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
