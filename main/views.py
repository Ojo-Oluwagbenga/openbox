from django.shortcuts import render
from django.shortcuts import redirect

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