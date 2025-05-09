import os
import json
import time
import datetime
import requests
from ..models import *
from .serializers import ModelSL
from .utils import *

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.db.models import Q



from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.conf import settings
from django.shortcuts import render
from django.http import HttpResponse
from django.views import View

class GeneralAPI:
    def replace_char(_string, ind, newchar):
        new_string = _string[:ind] + newchar + _string[ind+len(newchar):]
        return new_string
    
    def gettime(self, response):
        if (response.method == "POST"):
            t1 = time.time()
            return HttpResponse(json.dumps({"time":t1}))
        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def open_api(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            headers = {
                'Content-Type': 'application/json; UTF-8',
            }
            _data = data['data']
            _url = data['url']
            resp = requests.post(_url, data=json.dumps(_data), headers=headers)
            resp = json.loads(resp.content)
            return HttpResponse(json.dumps(resp))
        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def readKey(pubkey, del_on_read=False):
        key = KeyRecord.objects.filter(public_key=pubkey)
        prikey = '_'
        if (key):
            key = key[0]
            prikey = key.private_key
            if (del_on_read):
                key.delete()
            else:
                #UPDATE THE TIMING ON THIS KEY
                key.time = time.time()
                key.save()
                
        else:
            return False

        #DELETE ALL KEYS THAT HAS NOT BEEN QUERIED FOR PAST 30 DAYS.
        ago_30 = time.time() - 2592000
        key = KeyRecord.objects.filter(time__lt=ago_30).delete()
        
        
        return GeneralAPI.readHash(pubkey, prikey)

    def createKey(text):
        private_key = GeneralAPI.getHash(text, str(time.time()*random.random()))
        public_key = GeneralAPI.getHash(text, private_key)
        key_sl = ModelSL(data={"public_key":public_key,"private_key":private_key, "time":int(time.time())}, model=KeyRecord, extraverify={}) #CALLING AGAIN DUE TO MEMORY INTERFERENCE KINDA
        if (not key_sl.is_valid()):
            print("ERR: ", key_sl.cError())
        key_sl.save()
        
        return public_key

    def getHash(text, key):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'rx2K2Iq356-f6VLqCdqQCNRwPAA4Vpg6fFrAgXaeHrU=',
            iterations=390000,
        )
        _key = base64.urlsafe_b64encode(kdf.derive(str.encode(key)))
        f = Fernet(_key)
        enc = str(f.encrypt(str.encode(text)), 'UTF-8')

        #THIS IS TO PREVENT THE DOUBLE EQUAL TO SIGN AT THE END OF THE ENCRYPTION
        lenc = len(enc)
        last_char = enc[lenc-1]
        pre_last_char = enc[lenc-2]
        _enc = enc
        if (last_char == "="):
            _enc = GeneralAPI.replace_char(enc, lenc-1, "_")
        if (pre_last_char == "="):
            _enc = GeneralAPI.replace_char(enc, lenc-2, "__")

            
        enc = _enc
        
        return enc

    def readHash(hash, key):
        #CHECK KEY AND REPLACE THE REPLACED == WITH __
        lenc = len(hash)
        last_char = hash[lenc-1]
        pre_last_char = hash[lenc-2]
        _hash = hash
        if (last_char == "_"):
            _hash = GeneralAPI.replace_char(hash, lenc-1, "=")
        if (pre_last_char == "_"):
            _hash = GeneralAPI.replace_char(hash, lenc-2, "==")
        hash = _hash
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'rx2K2Iq356-f6VLqCdqQCNRwPAA4Vpg6fFrAgXaeHrU=',
            iterations=390000,
        )
        _key = base64.urlsafe_b64encode(kdf.derive(str.encode(key)))
        f = Fernet(_key)
        try:
            dec = str(f.decrypt(str.encode(hash)), 'UTF-8')
        except Exception as e:
            dec = False
        return dec

    def create_user_data(user_json):
        rand_text = str(time.time()*random.random())
        key_text = rand_text+user_json['user_code']
        lkey = GeneralAPI.getHash(key_text, "ENV('hash_key')") #THIS DOESN'T CHANGE THROUGH OUT THE SESSION
        
        rand_text2 = str(time.time()*random.random())
        rkey = GeneralAPI.getHash(rand_text, rand_text2) #THIS IS THE KEY ON RIGHT
        user_json['device_login_key'] = lkey
        userenc = GeneralAPI.getHash(json.dumps(user_json), rkey)
        


        key_sl = ModelSL(data={"public_key":lkey,"private_key":userenc, "time":int(time.time())}, model=KeyRecord, extraverify={}) 
        if (not key_sl.is_valid()):
            return False
        key_sl.save()

        key = rkey + "&" + lkey
        
        return key

    def read_user_data(joint_key):
        try:
            rkey = joint_key.split("&")[0]
            lkey = joint_key.split("&")[1]
            keyrec = KeyRecord.objects.filter(public_key=lkey)
            userenc = '_'
            if (keyrec):
                _key = keyrec[0]
                userenc = _key.private_key
            else:
                return False
            
            usertext = GeneralAPI.readHash(userenc, rkey)
            if (not usertext):
                keyrec.delete()
                return False
                #DELETE THE ENTRY
            
            # I WILL COME BACK AND THINK PROPERLY ON SECURE LOCAL API KEYS
            # rand_text2 = str(time.time())
            # rkey = GeneralAPI.getHash(rand_text2, "ENV('hash_key')") #THIS IS THE KEY ON RIGHT
            # userenc = GeneralAPI.getHash(usertext, rkey)

            # _key.private_key = userenc
            _key.time = time.time()
            _key.save() 

            user_json = json.loads(usertext)
            return {
                **user_json,
                # "new_key":rkey + "&" + lkey,
                # "keyrec":_key
            }
        except Exception as e:
            return False

    def writetofile(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            callresponse = {
                'passed': False,
                'response':400,
                'Message':"Not you, it's us. Please try again."
            }
            _b64 = data['b64file']
            name = data['name']
            b64 = _b64.replace('data:image/png;base64,', '')
            imgdata = base64.b64decode(b64)
            with open(name, 'wb') as f:
                f.write(imgdata)

            return HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def quickwriteandread(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            callresponse = {
                'passed': True,
            }
            text = data['text']
            f = open("testfile.txt", "r")
            ntext = f.read()
            callresponse["ntext"] = ntext

            if (text != "skip"):
                with open("testfile.txt", 'w') as f:
                    f.write(text)

            return HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def send_report(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            callresponse = {
                'passed': False,
                'response':400,
                'Message':"Not you, it's us. Please try again."
            }

            context = {
                "report_text": data['report_text'],
                "sender_email":response.session['user_data']['email']
            }
            html_message = render_to_string("mail_templates/report.html", context=context)
            plain_message = strip_tags(html_message)

            message = EmailMultiAlternatives(
                subject = "Report Report Report!!!",
                body = plain_message,
                from_email = response.session['user_data']['email'] ,
                to=['myoneklass@gmail.com']
            )

            message.attach_alternative(html_message, "text/html")
            message.send()

            
            return HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")


    def write_as_excel(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            callresponse = {
                'passed': False,
                'response':400,
                'Message':"Not you, it's us. Please try again."
            }
            folderpath = "main/static/"+data['folderpath'] #REMOVE THE MAIN DIR IN PRODUCTION
            data_text = data['payload']
            dataset = json.loads(data_text)
            try:
                shutil.rmtree(folderpath)
            except Exception as e:
                pass

            pathlib.Path(folderpath).mkdir(parents=True, exist_ok=True) 
            workbook = xlsxwriter.Workbook(folderpath + data['filename'])
            worksheet = workbook.add_worksheet()
            rc = 0
            kc = 0
            for row in dataset:  
                sortkeys = list(row.keys())
                sortkeys.sort()
                for key in sortkeys:
                    if key == 'a__code':
                        continue

                    if type(row[key]) == dict:#Means the freaker is the time packet
                        val = row[key]['time']
                        worksheet.write(rc, kc, val)
                        kc += 1
                        continue

                    val = row[key]
                    worksheet.write(rc, kc, val)
                    kc += 1
                rc += 1
                kc = 0

            workbook.close()
            return HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def read_excel():
        dirname = os.path.dirname(__file__)
        print (dirname)
        ws = xw.Book(dirname + '\Institutions\OAU;Obafemi Awolowo University/members.xlsx').sheets['Sheet1'] 
  
        v1 = ws.range("A2").value 
        v2 = ws.range("A3").value 
        r = ws.range("A2:E4").value 
        print("Row :", r)
        print("Result :", v1, v2)

    def delete_file(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            callresponse = {
                'passed': False,
                'response':400,
                'Message':"Not you, it's us. Please try again."
            }
            shutil.rmtree("main/static/" + data['folderpath']) #REMOVE THE MAIN DIR IN PRODUCTION
            return HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def init_user_session(response, data):
        response.session.flush()
        response.session['user_data'] = {}
        for key in data:
            response.session['user_data'][key] = data[key]

    def destroy_user_session(response):
        if (response.session['user_data']):
            user_code = response.session['user_data']['user_code']
            #CHECK PASSWORD
            user_set = User.objects.filter(user_code=user_code)
            if not user_set:
                return
            user = user_set[0]

            if (user.notification_key != 'nil'):
                FcmAPI.unsubscribe_from_topic([user.notification_key], user.class_code+"_today_class")
            user.notification_key = 'nil'
            user.save()
        response.session.flush()

    def get_version_update(UPDATE_CODE):
        __UPDATE_CODE = "1.0.0" #THIS MUST INCREASE AS CHANGES ARE MADE TO ANYTHING HERE
        __LATEST_APP_VERSION = "1.0.0" #THIS HOLDS THE MINIMUM COMPATIBILTY VALUE; 1.0.0 WORKS WITH 1.0.3 NOT 2.0.0 YOU GERRIT?

        __UPDATE_HOTDATA = {
            "dashboard":{
                "html":"" #THIS WILL HOLD THE STYLE AND JS ACTIONS
            },
            "general":{
                "html":"" #THIS WILL HOLD THE STYLE AND JS ACTIONS
            }
        }
        __APP_DATA = {
            'max_date': 1727110724.060 #EXPIRY DATE IN SECONDS EPOCH
        }

        if (__UPDATE_CODE != UPDATE_CODE):
            ret =  {
                "__UPDATE_HOTDATA":__UPDATE_HOTDATA,
                "__APP_DATA":__APP_DATA,
                "__UPDATE_CODE":__UPDATE_CODE,
                "__LATEST_APP_VERSION":__LATEST_APP_VERSION
            }
            return ret
        else:
            return None

class APIgenerals:
    def genUpdate(**kwargs):
        newData = kwargs['updates']
        fetchpair = kwargs['fetchpair']
        if (newData is None):
            newData = {}

        allowed = kwargs['allowed']


        model = kwargs['model']
        extraverify = kwargs['extraverify']

        callresponse = {
            'passed': True,
            'response':{},
            'error':{}
        }
        selection = []

        for k,v in newData.items():
            if (k in allowed):
                selection.append(k)

        sl = ModelSL(data=newData, model=model, selection=selection, extraverify=extraverify)
        runcheck = sl.is_valid()
        callresponse = sl.callresponse

        if (runcheck):
            qsets = model.objects.filter(**fetchpair)
            if not qsets:
                callresponse = {
                    'passed': False,
                    'response':{},
                    'Message': "Queryset not found",
                    'error':{}
                }
                return callresponse

            qset = qsets[0]
            for key in selection:
                setattr(qset, key, newData[key])
            qset.save()
            callresponse = {
                'passed': True,
                'response':{},
                'Message': "Update complete",
                'error':{}
            }
            return callresponse
        else:
            callresponse = sl.cError()
            return callresponse


    def get_model_data(**kwargs):
        model = kwargs['model']
        searches = kwargs['searches']

        #pass '__all__' to callable
        columns = kwargs['columns']
        ret = []

        #Get all the field in the Model model
        callables = [f.name for f in model._meta.fields]

        if (type(searches) is dict or type(columns) is list):
            if (columns == "__all__"):
                columns = callables
            else:
                columns = list(set(callables).intersection(columns))


            # The star before the passed data is to unpack the data
            qset = model.objects.only(*columns).filter(**searches)


            for mod in qset:
                mod.__dict__.pop("_state")
                mod.__dict__.pop("id")
                ret.append(mod.__dict__)
        else:
            ret = {
                'searches': "This JSON field is required",
                'columns': "This List is required",
            }
        return ret

    def generalFetch(**kwargs):
        model = kwargs['model']
        fetchset = kwargs['fetchset']
        fetchpair = kwargs['fetchpair']

        disallowed = kwargs.get('disallowed', ['id'])

        fields = [f.name for f in model._meta.get_fields()]
        if (fetchset == []):
            fetchset = [*fields]

        for x in disallowed:
            if x in fetchset:
                fetchset.remove(x)

        datas = model.objects.filter(**fetchpair).values(*fetchset)

        return [*datas]

    def delete_model_data(**kwargs):
        model = kwargs['model']
        searches = kwargs['searches']

        ret = model.objects.filter(**searches).delete()

        return {
            'passed': True,
            'error':{},
            'message':ret,
        }

    def checkmail(mail):
        pat = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        return re.match(pat,mail)


class UserAPI(View):
    def create_temporary(self, response):
        if (response.method == "POST"):
            fulldata =  json.loads(response.body.decode('utf-8'))
            data = fulldata['payload']
            callresponse = {
                'passed': False,
                'response':data,
                'error':{}
            }
            data['user_code'] = 'dummy'
            data['password'] = make_password(data['password'])
            data['join_time'] = int (time.time())
            print (data['join_time'])
            print (data)
            user_sl = ModelSL(data={**data}, model=UserTemp, extraverify={})

            if (not user_sl.is_valid()):
                callresponse = user_sl.cError()
                return (HttpResponse(json.dumps(callresponse)))

            callresponse = user_sl.callresponse

            if (not callresponse['passed']):
                return HttpResponse(json.dumps(callresponse))
            
            if (User.objects.filter(email=user_sl.validated_data.get('email')).count() > 0):
                callresponse['passed'] = False
                callresponse['error']['email'] = "The provided email is already registered"
                return HttpResponse(json.dumps(callresponse))
            
            user_sl = ModelSL(data={**data}, model=UserTemp, extraverify={}) #CALLING AGAIN DUE TO MEMORY INTERFERENCE KINDA
            user_sl.is_valid() #MUST BE CALLED TO PROCEED
            ins_id = user_sl.save().__dict__['id']
            user_code = numberEncode(ins_id, 10)
            user_sl.validated_data['user_code'] = user_code
            # user_sl.save()

            #SEND THE USER A CONFIRMATION MAIL
            #HASH KEY AND TIME
            stime = str(time.time())
            sec = str(stime.split(".")[0])
            text = user_code + "||" + sec
            
            enc = GeneralAPI.getHash(text, 'email_confirm')

            context = {
                "confirm_link": "https://oneklass.oauife.edu.ng/confirm_email/"+enc
            }
            html_message = render_to_string("mail_templates/confirmmail.html", context=context)
            plain_message = strip_tags(html_message)

            message = EmailMultiAlternatives(
                subject = "OneKlass mail confirmation",
                body = plain_message,
                from_email = None,
                to= [data['email']]
            )

            message.attach_alternative(html_message, "text/html")

            #INCLUDE THIS IN PRODUCTION
            message.send()


            callresponse = {
                'passed': True,
                'email':data['email'],
                'error':{},
                'enc':enc
            }
            return HttpResponse(json.dumps(callresponse))
        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def create(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            callresponse = {
                'passed': False,
                'response':data,
                'error':{}
            }
            data['user_code'] = 'dummy'
            data['password'] = make_password(data['password'])
            data['join_time'] = int (time.time())
            user_sl = ModelSL(data={**data}, model=User, extraverify={})

            if (not user_sl.is_valid()):
                callresponse = user_sl.cError()
                return (HttpResponse(json.dumps(callresponse)))

            callresponse = user_sl.callresponse

            if (not callresponse['passed']):
                return HttpResponse(json.dumps(callresponse))
            
            #CHECK IF USER NEVER EXISTED
            if (User.objects.filter(email=user_sl.validated_data.get('email')).count() > 0):
                callresponse['passed'] = False
                callresponse['error']['email'] = "The provided email is already registered"
                return HttpResponse(json.dumps(callresponse))
            
            user_sl = ModelSL(data={**data}, model=User, extraverify={}) #CALLING AGAIN DUE TO MEMORY INTERFERENCE KINDA
            user_sl.is_valid() #MUST BE CALLED TO PROCEED
            ins_id = user_sl.save().__dict__['id']
            user_code = numberEncode(ins_id, 10)
            user_sl.validated_data['user_code'] = user_code
            user_sl.save()

            
            callresponse = {
                'passed': True,
                'email':data['email'],
                'error':{},
            }
            return HttpResponse(json.dumps(callresponse))
        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def validate(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            callresponse = {
                'passed': False,
                'response':{},
                'error':{}
            }
            unique = data.get('uniqueid').strip()
            password = data.get('password')

            #CHECK USER'S VALIDIDTY
            user = User.objects.filter(Q(email=unique))
            if (not user):
                #CHECK IF IT IS THAT USER HAS NOT VERIFIED
                user = UserTemp.objects.filter(Q(email=unique) )
                if (not user):
                    callresponse["Message"] = "Login credential not valid. User not found."
                    return HttpResponse(json.dumps(callresponse))
                callresponse['Message'] = "User found"
                callresponse['passed'] = True
                callresponse['type'] = 'temp'
                return HttpResponse(json.dumps(callresponse))
            u_data = user[0]
            if (not check_password(password, u_data.password)):
                callresponse["Message"] = "Login credential not valid. User not found."
                return HttpResponse(json.dumps(callresponse))
            callresponse['Message'] = "User found"
            callresponse['passed'] = True

            new_data =  {
                'loggedin':True,
                "email":u_data.email,
                "user_type":u_data.user_type,
                "name":u_data.name,
            }
            callresponse['response'] = {**new_data}
            callresponse['time_data'] = time.time()
                        
            if (data.get('startSession') is not None):
                if (data.get('startSession')):
                    GeneralAPI.init_user_session(response, {**new_data})
                    response.session.set_expiry(864000) #10 DAYS - GETS UPDATED WHEN DASHBOARD LOADS/PAYMENT/INITIATE ATTENDANCE
                    callresponse['response']['message'] = ("User found and logged in")
                
            return HttpResponse(json.dumps(callresponse))
        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def getbalance(self, response):
        if (response.method == "POST"):
            callresponse = {
                'passed': False,
                'response':{},
                'error':{}
            }
            user_code = response.session['user_data']['user_code']

            #CHECK USER'S VALIDIDTY
            user = User.objects.filter(user_code=user_code)
            if (not user):
                return HttpResponse(json.dumps(callresponse))
            
            u_data = user[0]
            callresponse['response'] = {
                "cash_balance":u_data.cashbalance
            }
            callresponse['passed'] = True
            return HttpResponse(json.dumps(callresponse))
        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    @csrf_exempt
    def add_document(self, response):
        if response.method == 'POST' and response.FILES.get('document'):
            callresponse = {
                'passed': False,
                'response':{},
                'error':{}
            }
            # user_code = response.session['user_data']['user_code']
            # box_code = response.POST.get('box_code', 'boxcode')

            user_code = 'usercode'
            box_code = 'boxcode'
            uploaded_file = response.FILES['document']

            upload_subdir = os.path.join('uploaded', user_code, box_code)
            upload_dir = os.path.join(settings.MEDIA_ROOT, upload_subdir)
            os.makedirs(upload_dir, exist_ok=True)
            
            filename_no_ext, ext = os.path.splitext(uploaded_file.name)
            new_filename = f"{filename_no_ext}_{int(time.time())}{ext}"
            file_path = os.path.join(upload_dir, new_filename)

            with open(file_path, 'wb+') as dest:
                for chunk in uploaded_file.chunks():
                    dest.write(chunk)

            file_url = os.path.join(settings.MEDIA_URL, upload_subdir, new_filename)
            full_url = response.build_absolute_uri(file_url)
            
            callresponse['passed'] = True
            callresponse['response'] = {
                'upload_url':full_url
            }
            return HttpResponse(json.dumps(callresponse))
        return JsonResponse({'error': 'Invalid request'}, status=400)

    
class BoxAPI(View):
    def create(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            callresponse = {
                'passed': False,
                'response':data,
                'error':{}
            }
            data['box_code'] = 'dummy'
            data['create_time'] = int(time.time())

            box_sl = ModelSL(data={**data}, model=Box, extraverify={}) 
            box_sl.is_valid() # MUST BE CALLED TO PROCEED
            ins_id = box_sl.save().__dict__['id']
            box_code = numberEncode(ins_id, 10)
            box_sl.validated_data['box_code'] = box_code
            box_sl.save()
            
            callresponse = {
                'passed': True,
                'error':{},
            }
            return HttpResponse(json.dumps(callresponse))
        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def find_box_by_state(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            callresponse = {
                'passed': False,
                'response':{},
                'error':{}
            }
            
            boxes = Box.objects.filter(state=data['state'])
            if (not boxes):
                callresponse['response'] = "Boxes not found in this location"
                return HttpResponse(json.dumps(callresponse))
            
            retboxes = []
            for box in boxes:
                ret = {}
                if (data.get("columns")):
                    for column in data['columns']:
                        ret[column] = box[column]
                else:
                    ret['name'] = box.name
                    ret['address'] = box.address
                    ret['description'] = box.description

                retboxes.append(ret)
                

            callresponse['passed'] = True
            callresponse['response'] = {
                "boxes":retboxes
            }
            return HttpResponse(json.dumps(callresponse))
        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

class Box_messagesAPI(View):
    def add_message(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            callresponse = {
                'passed': True,
                'response':200,
                'comment_code':"comment_code",
            }

            create_data = {}
            user_code = response.session['user_data']['user_code']
            box_code = data['box_code']
            message_code = user_code + box_code + str (time.time())

            create_data['user_code'] = user_code
            create_data['box_code'] = box_code
            create_data['message_code'] = message_code
            create_data['message_side'] = 'user'
            create_data['message_type'] = data.get('message_type')
            create_data['text'] = data['text']
            create_data['document_url'] = data.get('document_url')
            create_data['time'] = time.time()

            box_sl = ModelSL(data={**create_data}, model=Box_message, extraverify={}) 
            box_sl.is_valid() # MUST BE CALLED TO PROCEED
            box_sl.save()
                       
            callresponse = {
                'passed': True,
                'response':200,
                'message_code':message_code,
            }

            return HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def fetch_messages(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))

            user_code = response.session['user_data']['user_code']
            box_code = data['box_code']
            time_range = data.get('time_range') # [timestart, timeend]
            count = int (data.get('count', 10))
            
            searchquery = {
                "user_code": user_code,
                "box_code": box_code,
            }

            # Check if time_range is provided (it should be a tuple or list of 2 values: start time, end time)
            if time_range:
                searchquery['time__range'] = (time_range[0], time_range[1])
                
            # Query the database with the searchquery dictionary
            messages = Box_message.objects.filter(**searchquery).order_by('time')

            # Limit the number of messages if `count` is provided
            if count:
                messages = messages[:count]

            # Prepare the response
            callresponse = {
                'passed': True,
                'response': 200,
                'queryset': list(messages.values())  # Convert QuerySet to a list of dictionaries
            }

            return HttpResponse(
                json.dumps(callresponse),
                content_type="application/json"
            )

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

class TransactionAPI:
    model = Transaction

    extraverify = {
        'name':[4, 20, 'def'],
    }

    def b64_to_cv2(base64_data):
        nparr = np.fromstring(base64_data.decode('base64'), np.uint8)
        return cv2.imdecode(nparr, cv2.IMREAD_ANYCOLOR)

    def tozero (val):
        return 0 if (val<0) else val

    def create(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8')).get('payload')
            callresponse = {
                'passed': False,
                'response':400,
                'Message':"Something broke. Please try again"
            }

            if not data['imageset']:
                data['imageset'] = ['-']
            data['creatorid'] = response.session['user_data']['user_code']
            creator = data['creatorid']
            data['admins'] = [creator]
            data['users'] = [creator]
            data['status'] = '1'
            data['invited_classes_groups'] = []
            data['class_code'] = response.session['user_data']['class_code']
            data['create_date'] = datetime.now().isoformat()
            data['total_received'] = 0
            data['total_withdrawn'] = 0


            data['receipt_data'] = {
                "header":"One Klass Digital Receipt",
                "school":"Obafemi Awolowo University",
                "location":"Ile Ife",
                'receipt manager':"Treasurer",
                "manager_sign":"",
                "collector_logo":"../static/receipt/img/oneklass_logo.png",
            }
            data['paydata'] =  {}

            callresponse = {
                'passed': False,
                'response':{},
                'error':{}
            }
            data['channel_code'] = 'dummy'

            sl = ModelSL(data=data, model=PaymentChannel, extraverify=self.extraverify)
            
            

            if (sl.is_valid()):
                callresponse = sl.callresponse
            else:
                callresponse = sl.cError()

            if (callresponse['passed']):
                ins_id = sl.save().__dict__['id']
                channel_code = numberEncode_upper(ins_id, 5)
                sl.validated_data['channel_code'] = channel_code
                sl.validated_data['channel_short_code'] = 'PAY-' + channel_code
                sl.save()
                c_code = sl.validated_data['channel_code']
                callresponse['response']['channel_code'] = c_code

                user = User.objects.filter(user_code=creator)[0]
                user.paymentchannels.append(c_code)
                user.save()

                url = './payout/'+c_code

                NotificationAPI.send({
                    "callback_url":url,
                    "text": "Payment channel created for <b>"+data['name']+"</b>. Click to view and invite payers",
                    "category":"upd",
                    "owners":[creator],
                    "channel_code":c_code,
                    "otherdata":{}, #Any other data useful for that notification
                })

            return HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")


    def fetch(self, response):
        if (response.method == "POST"):
            data = json.loads(response.body.decode('utf-8'))

            fetchpair =  data.get('fetchpair', {})
            fetchset =  data.get('fetchset', [])
            if (data.get("elaborate_groups")):
                fetchset.extend(['users','invited_classes_groups']) #I NEED TO GET USERS HERE SO I CAN USE THAT TO COLLECT ALL THE RELATED GROUPS

            retpack = APIgenerals.generalFetch(model=PaymentChannel, fetchset=fetchset, fetchpair=fetchpair)
            # return HttpResponse(json.dumps('ret'))

            if (data.get("elaborate_groups")):
                for pchan in retpack:
                    users = pchan['users']
                    users_groups = User.objects.filter(user_code__in=users, paymentchannels__contains=[pchan['channel_code']]).values('groups','class_code')
                    owners=pchan['invited_classes_groups']
                    for user in users_groups:
                        if (user['class_code'] not in owners):
                            owners.append(user['class_code'])
                        for gpcode in user['groups']:
                            if (gpcode not in owners):
                                owners.append(gpcode)

                    cl_obj = {}
                    classes = []
                    groups = []
                    for code in owners:
                        clen = len(code.split("grp_")) #CHECK IF CODE IS GROUP OF A CLASS
                        if clen == 1: #MEANS THIS IS A CLASS
                            classes.append(code)
                        else:
                            groups.append(code)
                    if (len(groups) > 0):
                        grp = Group.objects.annotate(name=F("group_name")).filter(group_code__in=groups).values('name', 'group_code')
                        for fObj in grp:
                            cl_obj[fObj['group_code']] = fObj['name']
                    if (len(classes) > 0):
                        grp = Class.objects.filter(class_code__in=classes).values('name', 'class_code')
                        for fObj in grp:
                            cl_obj[fObj['class_code']] = fObj['name']

                    pchan['class_data'] = cl_obj
                    pchan['owners'] = owners

            callresponse = {
                'passed': True,
                'response':200,
                'queryset':retpack
            }
            return  HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def fetch_foruser(self, response):
        if (response.method == "POST"):
            data = json.loads(response.body.decode('utf-8'))
            callresponse = {
                'passed': False,
                'response':200,
                'attendances':[]
            }
            if (response.session.get("user_data")):
                user_json = response.session['user_data']
            else:
                print("checking platform payment", data)
                if (data.get("platform") == 'mobile'):
                    user_json = GeneralAPI.read_user_data(data.get('pub_api_key'))
                    print("reached the channel", user_json)
                    if (not user_json):                        
                        return  HttpResponse(json.dumps(callresponse))
                else:
                    return  HttpResponse(json.dumps(callresponse))
                
            user_code = user_json['user_code']

            if (data.get('invites_only')):
                #IF INVITES IS TRUE, IT FETCHES ALL THE ATTENDANCES THAT HAS INVITED THE USER'S CLASS OR GROUPS
                user_code = user_json['user_code']
                userset = User.objects.filter(user_code=user_code).values("groups", "class_code", "paymentchannels", "paymentchannels_blacklist")[0]
                query = {
                    'invited_classes_groups__overlap': [userset['class_code'], *userset['groups']],
                }
            else:
                #IF INVITES IS FALSE, IT FETCHES ALL THE ATTENDANCES THAT USER HAS JOINED
                userset = User.objects.filter(user_code=user_code).values("paymentchannels")[0]
                query = {
                    'channel_code__in': userset['paymentchannels']
                }

            channels = PaymentChannel.objects.filter(**query).order_by('id')
            if not channels:
                callresponse = {
                    'passed': True,
                    'response':200,
                    'queryset':[],
                }
                return HttpResponse(json.dumps(callresponse))


            retpack = []
            
            for chn in channels:                
                if (data.get('invites_only')):
                    #PREVENT ALL PAYCHANNELS THAT THE USER HAS JOINED OR REJECTED
                    if (chn.channel_code in userset['paymentchannels'] or chn.channel_code in userset['paymentchannels_blacklist']):
                        continue
                

                total_left = chn.price

                if (chn.paydata.get(user_code)):
                    total_left = chn.paydata[user_code]['total_left']
                        
                if (data.get('incompletes_only')):
                    if (total_left == 0):
                        continue
                    
                
                mono = {
                    "channel_code":chn.channel_code,
                    "time":chn.create_date,
                    "name":chn.name,
                    "has_deadline":chn.has_deadline,
                    "deadline_text":chn.deadline_text,
                    "deadline_digit":chn.deadline_digit,
                    "status":chn.status,
                    "creatorid":chn.creatorid,
                    "price":chn.price,
                    "total_left":total_left,
                }
                retpack.append(mono)

            # if (user_json.get("keyrec")):
            #     pass
                # user_json['keyrec'].save()
            callresponse = {
                'passed': True,
                'response':200,
                "channels_found":True,
                'queryset':retpack,
                # 'big':[*channels.values()]
            }
            return  HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def fetch_transaction(self, response):
        if (response.method == "POST"):
            transact_code =  json.loads(response.body.decode('utf-8')).get('receipt_code', [])
   
            fetchpair = {'transact_code' : transact_code}
            fetchset = ['payer_code','amount','type', 'date']

            callresponse = {
                'passed': False,
                'response':200,
                'Message':""
            }

            retpack = APIgenerals.generalFetch(model=Transaction, fetchset=fetchset, fetchpair=fetchpair)
            if (len(retpack) == 0):
                callresponse['Message'] = "Transaction not found!"
                return  HttpResponse(json.dumps(callresponse))

            retpack = retpack[0]

            callresponse = {
                'passed': True,
                'response':200,
                'queryset':{**retpack},

            }
            return  HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def fetch_transactions(self, response):
        if (response.method == "POST"):
            user_code = response.session['user_data']['user_code']
            
            fetchpair = {'payer_code' : user_code}
            fetchset = ['payer_code','amount','type', 'date']

            callresponse = {
                'passed': False,
                'response':200,
                'Message':""
            }

            retpack = APIgenerals.generalFetch(model=Transaction, fetchset=fetchset, fetchpair=fetchpair)
            if (len(retpack) == 0):
                callresponse['Message'] = "Transaction not found!"
                return  HttpResponse(json.dumps(callresponse))

            retpack = retpack[0]

            callresponse = {
                'passed': True,
                'response':200,
                'queryset':[*retpack],
            }
            return  HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def has_outstanding(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))

            user_code = response.session['user_data']['user_code']
            outstanding = PayTransact.objects.filter(user_code=user_code)
            if outstanding:
                callresponse = {
                    'passed': True,
                    'response':200,
                    'has_outstanding': True,
                }
            else:
                callresponse = {
                    'passed': True,
                    'response':200,
                    'has_outstanding': False,
                }

            return HttpResponse(json.dumps(callresponse))


        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def clear_outstanding(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            user_code = response.session['user_data']['user_code']

            outstanding = PayTransact.objects.filter(user_code=user_code)
            if not outstanding:
                callresponse = {
                    'passed': False,
                    'response':200,
                    'Message':"No outstanding transaction",
                }
                return HttpResponse(json.dumps(callresponse))

            outstanding = outstanding[0]

            reference = outstanding.reference_code
            print ("Reference: " + reference )
            pay_code = outstanding.item_code

            params = {
                # "Authorization":"Bearer sk_live_eabc4113227dc2530121c270fde2497ca123527c",
                "Authorization":"Bearer sk_test_Y3wqHLPb3CtT3mjQY2oRumqSxWwHdTMNPerECzyZ",
            }
            check_req = requests.get("https://google.com", headers=params)
            print (check_req)
            check_req = requests.get("https://api.korapay.com/merchant/api/v1/charges/"+reference, headers=params)
            check_req = check_req.json()
            print (check_req)


            if (not check_req.get('status')):
                callresponse = {
                    'passed': False,
                    'response':201,
                    'data':reference,
                    'Message':"This Transaction did not go through and thus deleted!",
                }
                outstanding.delete()
                return HttpResponse(json.dumps(callresponse))

            tdata = check_req.get('data')

            if (tdata['status'] != "success"):
                callresponse = {
                    'passed': False,
                    'response':201,
                    'data':reference,
                    'transaction_data':tdata,
                    # 'Message':tdata['gateway_response'],
                    'Message':"Transaction did not go through. Record deleted!",
                }
                outstanding.delete()
                return HttpResponse(json.dumps(callresponse))


            amount_paid = float(tdata['amount']) #Already in Naira
            charges = 0
            amount_paid = amount_paid - charges

            callresponse = self.add_user_payment(response=response, channel_code=pay_code, amount=amount_paid, pay_req_data=tdata)
            return HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def startpayment(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            callresponse = {
                'passed': False,
                'response':200,
                'Message':"Something broke. Try again",
            }

            #Complete and destroy outstandng transactions
            user_code = response.session['user_data']['user_code']
            outstanding = PayTransact.objects.filter(user_code=user_code)
            if outstanding:
                callresponse['Message'] = "Click clear outstanding transaction before proceeding"
                callresponse['error_type'] = "outstanding"
                return HttpResponse(json.dumps(callresponse))

            
            date = datetime.now().isoformat()
            stime = str(round(time.time() * 1000))
            reference_code = user_code + "_" + numberEncode(stime, len(stime))

            createset = {
                "reference_code":reference_code,
                "user_code":user_code,
                "date": date
            }

            PayTransact.objects.create(**createset)

            callresponse = {
                'passed': True,
                'response':200,
                'reference_code':reference_code,
            }

            return HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def verify_add(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))

            reference = data['reference']
            pay_code = data['pay_code']
            user_code = response.session['user_data']['user_code']

            params = {
                # "Authorization":"Bearer sk_live_eabc4113227dc2530121c270fde2497ca123527c",
                "Authorization":"Bearer sk_test_Y3wqHLPb3CtT3mjQY2oRumqSxWwHdTMNPerECzyZ",
            }
            check_req = requests.get("https://api.korapay.com/merchant/api/v1/charges/"+reference, headers=params)
            check_req = check_req.json()

            if (not check_req.get('status')):
                callresponse = {
                    'passed': False,
                    'response':201,
                    'Message':"This Transaction did not go through",
                }
                PayTransact.objects.filter(user_code=user_code)[0].delete()
                return HttpResponse(json.dumps(callresponse))

            tdata = check_req.get('data')

            #CHECK IF THE REQUEST WAS A SUCCESS ON THE THIRD PARTY END
            if (tdata['status'] != "success"):
                callresponse = {
                    'passed': False,
                    'response':201,
                    'data':reference,
                    'transaction_data':tdata,
                    # 'Message':tdata['gateway_response'],
                    'Message':"Transaction did not go through. Record deleted!",
                }
                PayTransact.objects.filter(user_code=user_code)[0].delete()
                return HttpResponse(json.dumps(callresponse))
            
            #CHECK IF THE REQUEST IS STILL ACTIVE: HAS AN ENTRY OF THE REFERENCE CODE IN THE PAYTRANSACT 
            ptransact = PayTransact.objects.filter(reference_code=reference)
            if not ptransact:
                callresponse = {
                    'passed': False,
                    'response':201,
                    'Message':"The reference code is used or inactive!",
                }
                return HttpResponse(json.dumps(callresponse))

            amount_paid = float(tdata['amount']) #To Naira
            charges = 0
            # if (amount_paid >= 2600):
            #     charges = 100
            amount_paid = amount_paid - charges
            # if (amount_paid > 2000):
            #     callresponse = {
            #         'passed': False,
            #         'response':201,
            #         'Message':"We are sorry, you can not pay more than #2000 at once!",
            #     }
            #     PayTransact.objects.filter(user_code=user_code)[0].delete()
            #     return HttpResponse(json.dumps(callresponse))

            callresponse = self.add_user_payment(response=response, channel_code=pay_code, amount=amount_paid, pay_req_data=tdata)
            return HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def add_user_payment(**kwargs):
        response = kwargs['response']
        amount = kwargs['amount']
        user_code = response.session['user_data']["user_code"]

        amount_paid = amount
        text = ['','']


        userdt= User.objects.filter(user_code=user_code)[0]        
        userdt.cashbalance += amount_paid

        #Insert Transaction into table
        try:
            recent_transact = Transaction.objects.latest("id")
        except Exception as e:
            recent_transact = None

        balance2date = 0
        if (recent_transact):
            balance2date = recent_transact.balance_to_date

        transaction_data = {
            "transact_code":"__",
            "payer_code":user_code,
            "type":"in",
            "balance_to_date":balance2date+amount_paid,
            "amount":amount_paid,
            "date":datetime.now().isoformat(),
        }
        sl = ModelSL(data=transaction_data, model=Transaction, extraverify={})

        if (sl.is_valid()):
            callresponse = sl.callresponse
        else:
            callresponse = sl.cError()
            return callresponse

        if (callresponse['passed']):
            ins_id = sl.save().__dict__['id']
            sl.validated_data['transact_code'] = numberEncode(ins_id, 10)
            sl.save()

        PayTransact.objects.filter(user_code=user_code)[0].delete()

        NotificationAPI.send({
            "callback_url":"-",
            "text":"Your payment has been added successfully",
            "category":"pay",
            "owners":[user_code],
            "otherdata":{}, #Any other data useful for that notification
        })


        #ADD PAYMENT REPORT TO THE ADMIN DASHBOARD
        # adb = Admin_dashboard.objects.filter(institution=qset.institution)
        # if not adb:
        #     AdminAPI.create(qset.institution)
        #     adb = Admin_dashboard.objects.filter(institution=qset.institution)
        # adb = adb[0]
        # #----REMOVE OLDER THAN 30 DAYS REPORT
        # recent = [*adb.recent_payments]
        # adb.recent_payments = []
        # mtime = time.time()
        # days_30 = 2592000 #IN SECONDS
        # for pdt in recent:
        #     if (mtime - pdt['time'] < days_30): #TIME DIFF IS LESSER THAN 30 DAYS
        #         adb.recent_payments.append(pdt)
        # #ADD THE LATEST
        # adb.recent_payments.append({
        #     "pay_code":qset.channel_code,
        #     "payer":user_code,
        #     "amount":amount_paid,
        #     "date":datetime.now().isoformat(),
        #     "time":time.time()
        # })
        # adb.save()


        callresponse = {
            'passed': True,
            'response':200,
            'Message':"Payment successfully completed!",
        }
        return callresponse

    def update(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            user_code = response.session['user_data']['user_code']

            updates = data['updates']
            fetchpair = data['fetchpair']

            callresponse = self.subUpdate(self, updates, fetchpair)

            print("The calll", callresponse)

            return HttpResponse(json.dumps(callresponse))
        else:
            return HttpResponse("<div style='position: fixed; height: 100vhb ; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def subUpdate(self, updates, fetchpair):
        return APIgenerals.genUpdate(updates=updates, allowed=['name', 'receipt_data', 'status','deadline_digit', 'deadline_text', 'has_deadline'], model=PaymentChannel, extraverify=self.extraverify, fetchpair=fetchpair)

    def verifyreceipt(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            callresponse = {
                'passed': False,
                'response':201,
                'Message':"Broken pipe! It's us, not you! Please try again."
            }
            qr1 = data['qrcode']
            text = AttendanceAPI.readQR(qr1)
            #You should freaking confirm the data here from the DB
            callresponse = {
                'passed': True,
                'response':200,
                'code':text,
            }

            return HttpResponse(json.dumps(callresponse))
        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def fetch_banks(self, response):
        if (response.method == "POST"):
            check_req = requests.get("https://api.paystack.co/bank")
            return  HttpResponse(json.dumps(check_req.json()))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def verify_bank_account(self, response):
        if (response.method == "POST"):
            data = json.loads(response.body.decode('utf-8'))
            params = {
                "Authorization":"Bearer sk_test_1a4fa744b46e01060f7a39564a77171a98034c09",
            }
            check_req = requests.get("https://api.paystack.co/bank/resolve?account_number="+data['account_number']+"&bank_code=" + data['bank_code'], headers=params)
            return  HttpResponse(json.dumps(check_req.json()))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

class NotificationAPI:

    extraverify = {}
    def fetch_user_notifications(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))

            user_code = response.session['user_data']['user_code']
            # class_code = response.session['user_data'].get('class_code', '-')

            fetchset = []

            user_code = response.session['user_data']['user_code']
            # userset = User.objects.filter(user_code=user_code).values("groups")
            # ugroups = userset[0]['groups']
            # ngroups = []
            # for gp in ugroups:
                # ngroups.append("__"+gp + "__")

            querypair={
                "owners__overlap":["__all__", user_code] #Gets where the owners list contains any of the passed
            }

            qset = Notification.objects.values().filter(**querypair).order_by('-id')

            if (qset.count() == 0):
                callresponse = {
                    'passed': False,
                    'response':201,
                    'queryset':[]
                }
                return HttpResponse(json.dumps(callresponse))


            callresponse = {
                'passed': True,
                'response':200,
                'queryset':[*qset]
            }
            return  HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def send(dataset):
        '''
        owner_set is sent as
                ['__all__'] for every user on Omega class
                ['__class_code1__', '__class_code2__'] for every user in a class, class_code must come with underscores as shown
                ['qvdy', "sded"] for every user as contained
            dataset sould be in format
                dataset = {
                    "callback_url":"curl",
                    "text":"text",
                    "time":"time",
                    "category":"category",
                    "upd" for Updates(pay created, pay ending),
                    "cla" for Class (concerning class creations, class updates, attendance creates)
                    "rem" for Reminder(class coming up, pay ending, pay not yet attendeds)
                    "soc" for socials (replies to comments, comments add);
                    'exa' for exams (exams and test updates)
                    "gen" for general (paycomplete from omega, )
                    "owners":[] #As defined by owner_set above
                    "otherdata":{} #Any other data useful for that notification
                }
        '''

        callresponse = {
            'passed': True,
            'response':{},
            'error':{}
        }
        current_date = datetime.now().isoformat()
        dataset['time']=current_date

        dataset['noti_code'] = "dummy"
        sl = ModelSL(data=dataset, model=Notification, extraverify={})

        if (sl.is_valid()):
            callresponse = {**sl.callresponse}
        else:
            callresponse = {**sl.cError()}

        if (callresponse['passed']):
            ins_id = sl.save().__dict__['id']
            sl.validated_data['noti_code'] = numberEncode(ins_id, 6)
            sl.save()
            callresponse['response']['notification_code'] = sl.validated_data['noti_code']
        else:
            print('not saved to db')

        owners = [*dataset['owners']]
        classlist = []
        userlist = []
        grouplist = []
        querypair = {}
        _all = False

        if "__all__" in owners:
            _all = True
            owners.remove("__all__")
        else:
            for own in owners:
                if own.startswith("__"):
                    gen_code = own.split("__")[1]
                    group_code = gen_code.split("grp_")
                    if (len(group_code) == 1):
                        classlist.append(gen_code)
                    else:
                        grouplist.append(group_code[1])
                else:
                    userlist.append(own)
        if _all:
            User.objects.all().update(unread_notice_count=F('unread_notice_count')+1)
        else:
            User.objects.filter(Q(user_code__in=userlist) | Q(class_code__in=classlist) | Q(groups__overlap=grouplist)).update(unread_notice_count=F('unread_notice_count')+1)

        # return #FIX THIS WHEN YOU GET THE WEBSOCKET WORKING PROPERLY
        try:
            # channel_layer = get_channel_layer()
            # for listener in dataset['owners']:
            #     async_to_sync(channel_layer.group_send)(
            #         "NOTIF_LISTENER_"+listener,
            #         {
            #             "type": "mono_disburse", #Calling the function defined in the consumer here
            #             "message": dataset,
            #         },
            #     )
            return callresponse
        except Exception as e:
            return callresponse

    def create(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8')).get('payload')


            dataset = {
                "callback_url":"-",
                "text":data['text'],
                "time":"",
                "category":data["category"],
                # "upd" for Updates(pay created, pay ending),
                # "cla" for Class (concerning class creations, class updates, attendance creates)
                # "rem" for Reminder(class coming up, pay ending, pay not yet attendeds)
                # "soc" for socials (replies to comments, comments add);
                # 'exa' for exams (exams and test updates)
                # "gen" for general (paycomplete from omega, )
                "owners":data['classes'], #As defined by owner_set above
                "otherdata":{
                    "creator_name":response.session['user_data']['name']
                } #Any other data useful for that notification
            }

            if not dataset['owners']:
                callresponse = {
                    'passed': False,
                    'response':{},
                    'Message':'Classes not set'
                }
                return HttpResponse(json.dumps(callresponse))

            #SEND ALL THE USERS NOTIFICATION
            users_data = User.objects.filter(Q(class_code__in=dataset['owners']) | Q(groups__overlap=dataset['owners'])).values("user_code","name",'notification_key')
            if users_data.count() == 0:
                pass
            
            messagePacket = []
            title = 'Lectures'
            body = "Hey Ojo, a new queue has been added to Fluid Mechanics' attendance. Coming on by Monday, 23/06 at 2:30pm."
            for usr in users_data:
                if (usr['notification_key'] != None):
                    messagePacket.append({
                        "user_code":usr['user_code'],
                        "registration_token":usr['notification_key'],
                        "title":title,
                        "body":body,
                    })
                
            FcmAPI.send_notification(messagePacket)


            #Since all owners will be listening over class level socket in this case -- This should be reviwed
            newcl = []
            for cl in dataset['owners']:
                newcl.append("__" + cl + "__") #class be like __AD3asd__, group be like __grp_se3jc__

            if (response.session['user_data']['user_type'] == 'instructor'):
                newcl.append(response.session['user_data']['user_code'])


            dataset['owners'] = newcl
            try:
                ret = self.send(dataset)
                return HttpResponse(json.dumps(ret))
            except Exception as e:
                ret = {
                    'passed':False,
                    'errorcode':201,
                    "Message": 'Unable to auto send broadcast'
                }
                return HttpResponse(json.dumps(ret))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")
