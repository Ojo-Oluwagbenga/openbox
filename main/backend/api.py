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
from django.db.models import F

import random
import pandas as pd
import ast
from datetime import datetime



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

import google.auth.transport.requests
from google.oauth2 import service_account
from firebase_admin import messaging, db
from firebase_admin import credentials
import firebase_admin


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

class FcmAPI:
    PROJECT_ID = 'oneklass-v2'
    BASE_URL = 'https://fcm.googleapis.com'
    FCM_ENDPOINT = 'v1/projects/' + PROJECT_ID + '/messages:send'
    FCM_URL = BASE_URL + '/' + FCM_ENDPOINT
    SCOPES = ['https://www.googleapis.com/auth/firebase.messaging']

    def _get_access_token():
        credentials = service_account.Credentials.from_service_account_file(
            'service_account.json', scopes=FcmAPI.SCOPES)
        request = google.auth.transport.requests.Request()

        credentials.refresh(request)
        return credentials.token
    
    def get_firedb_data(address):
        # Initialize the app with a service account, granting admin privileges
        try:
            cred = credentials.Certificate('service_account.json')
            firebase_admin.initialize_app(cred, {
                'databaseURL': "https://oneklass-v2-default-rtdb.firebaseio.com"
            })
            
        except Exception as e:
            print (e)
            print("Unable")
            pass

        # Reference to your Firebase database
        ref = db.reference(address)

        # Fetching data from the database
        snapshot = ref.get()

        # RETURN the retrieved data
        return [ref, snapshot]

    def unsubscribe_from_topic(reg_tokens, topic):
        if not firebase_admin._apps:
            cred = credentials.Certificate('service_account.json') 
            firebase_admin.initialize_app(cred)
        messaging.unsubscribe_from_topic(reg_tokens, topic)
        
    def subscribe_to_topic(reg_tokens, topic):
        if not firebase_admin._apps:
            cred = credentials.Certificate('service_account.json') 
            firebase_admin.initialize_app(cred)
        messaging.subscribe_to_topic(reg_tokens, topic)

    def send_notification(packet):
        '''
            packet:[
                {
                    "user_code":ucode,
                    "registration_token":reg_token,
                    "title":the_title,
                    "body":the_body,
                }
            ]
        '''

        headers = {
            'Authorization': 'Bearer ' + FcmAPI._get_access_token(),
            'Content-Type': 'application/json; UTF-8',
        }
        resp = None
        for pck in packet:
            fcm_message = {
                'message': {
                    'token':pck['registration_token'],
                    'notification': {
                        'title': pck['title'],
                        'body': pck['body'],
                    },
                    "android": {
                        "notification": {
                            "sound": "default"
                        }
                    },
                }
            }
            resp = requests.post(FcmAPI.FCM_URL, data=json.dumps(fcm_message), headers=headers)
           
        return resp

    def send_topic_notification(data):
        '''
        data = {
            topic:"",
            title:"",
            body:"",
        }
        '''
        # response = FcmAPI.subscribe_to_topic(registration_tokens, "topic") == USER MUST BE SUBSCRIBED LIKE THIS
        headers = {
            'Authorization': 'Bearer ' + FcmAPI._get_access_token(),
            'Content-Type': 'application/json; UTF-8',
        }
        fcm_message = {
            "message": {
                "topic": data["topic"],
                "notification": {
                    "title":data['title'],
                    "body":data['body']
                },
                "webpush": {
                    "fcm_options": {
                        "link": "https://oneklass.oauife.edu.ng"
                    }
                }
            }
        }
        resp = requests.post(FcmAPI.FCM_URL, data=json.dumps(fcm_message), headers=headers)
        return resp
    
    #THE FUNCTIONS BELOW WILL MANAGE THE AUTO ATTENDANCE AS REQUEST IS SENT TO THEM
    
    #THIS WILL HANDLE BOTH THE PRE AND POST NOTIFICATION FOR ATTENDANCE
    @csrf_exempt
    def openManager(response, apimethod): 
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))

            #TO ENSURE NOT JUST ANYONE WITH THE LINK CAN START QUIUING NOTIFICATION 
            if (data.get("secret_code") != 'my_secret_code'):
                callresponse = {
                    'passed': False,
                    'Message':"Invalid Access"
                }
                return  HttpResponse(json.dumps(callresponse))
            
            return getattr(FcmAPI, apimethod)(response)

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def attendance_notify(response): 
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            data = data['needed_data']
            attendance_code = data.get("attd_code")

            if (data.get('type') == 'pre'):
                attds = Attendance.objects.filter(attendance_code=attendance_code)
                if (attds):
                    attd = attds[0]
                    users = attd.users 

                    #SEND ALL THE ADMINS OPENING NOTIFICATION
                    users_data = User.objects.filter(user_code__in=attd.admins).values("user_code","name",'notification_key')
                    messagePacket = []
                    title = attd.course_code +': Attendance in 10mins'
                    sub_body = attd.course_name+"'s attendance is set to be up in 10mins. Click on the activate to start when it's time"
                    for usr in users_data:
                        if (usr['notification_key'] != 'nil'):
                            messagePacket.append({
                                "user_code":usr['user_code'],
                                "registration_token":usr['notification_key'],
                                "title":title,
                                "body":"Hi " + usr['name'].split(" ")[0] + ", your " + sub_body,
                            })
                    FcmAPI.send_notification(messagePacket)

                    #SEND ALL THE APP USERS NOTIFICATION
                    users_data = User.objects.filter(user_code__in=users).values("user_code","name",'notification_key')
                    if users_data.count() > 0:
                        messagePacket = []
                        title = attd.course_code +': Attendance in 10mins!'
                        sub_body = attd.course_name+"'s attendance is set to be up in 10mins"
                        for usr in users_data:
                            if (usr['notification_key'] != 'nil'):
                                messagePacket.append({
                                    "user_code":usr['user_code'],
                                    "registration_token":usr['notification_key'],
                                    "title":title,
                                    "body":"Hey " + usr['name'].split(" ")[0] + ", " + sub_body,
                                })             
                        resp = FcmAPI.send_notification(messagePacket)


                #EXTRACT FOR ALL USERS IN THE ATTENDANCE
                pass
            if (data.get('type') == 'post'):
                #EXTRACT FOR ONLY USERS THAT HAVE NOT MARKED
                attds = Attendance.objects.filter(attendance_code=attendance_code)
                if (attds):
                    attd = attds[0]
                    users = [*attd.users]

                    #FILTER ONLY USERS THAT HAVE NOT MARKED
                    mark_code = 'marked_users_'+str(attd.attendance_data['mark_index'])
                    marked_users = list(attd.attendance_data['indices'][mark_code].keys())                                       
                    users = [i for i in users if i not in marked_users]
                    

                    #SEND UNMARKED USERS NOTIFICATION
                    users_data = User.objects.filter(user_code__in=users).values("user_code","name",'notification_key')
                    if users_data.count() == 0:
                        pass

                    messagePacket = []
                    title = attd.course_code +': Closing soon!'
                    sub_body = "seems you have not marked your presence in the ongoing poll, the record closes soon. Click this pop to proceed marking."
                    for usr in users_data:
                        if (usr['notification_key'] != 'nil'):
                            messagePacket.append({
                                "user_code":usr['user_code'],
                                "registration_token":usr['notification_key'],
                                "title":title,
                                "body":"Hey " + usr['name'].split(" ")[0] + ", " + sub_body,
                            })
                    FcmAPI.send_notification(messagePacket)

            callresponse = {
                'passed': True,
                'response':200,
            }
            return  HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def attendance_queue_prompt(response): 
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            data = data['needed_data']
            attendance_code = data.get("attd_code")
            user_code = data.get("user_code") #THE ADMIN THAT CLOSED THE LAST POLL

            
            #SEND NOTIFICATION TO THE USER TO QUEUE NEW ATTENDANCE
            attds = Attendance.objects.filter(attendance_code=attendance_code)
            if (attds):
                attd = attds[0]
                
                users_data = User.objects.filter(user_code=user_code).values("user_code","name",'notification_key')
                messagePacket = []
                title = attd.course_code +': Call to queue'
                sub_body = attd.course_name+"'s attendance. Click to view data and queue for the next class"
                for usr in users_data:
                    if (usr['notification_key'] != 'nil'):
                        messagePacket.append({
                            "user_code":usr['user_code'],
                            "registration_token":usr['notification_key'],
                            "title":title,
                            "body":"Hi " + usr['name'].split(" ")[0] + ", You just closed " + sub_body,
                        })
                FcmAPI.send_notification(messagePacket)
        
            callresponse = {
                'passed': True,
                'response':200,
                'queryset':"retset"
            }
            return  HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def payments_reminder(response): 
        if (response.method == "POST"):
            #SEND THE NECESSARY USERS THEIR PENDING PAYMENTS
            channels = PaymentChannel.objects.all()
            unbalanced_users = {}
            for channel in channels:
                for user_code in channel.users:
                    unbalanced = False
                    if (channel.paydata.get(user_code)):
                        unbalanced = channel.paydata[user_code]['total_left'] != 0
                    else:
                        unbalanced = True

                    if (unbalanced):
                        if (unbalanced_users.get(user_code)):
                            unbalanced_users[user_code]['channel_names'].append(channel.name)
                        else:
                            unbalanced_users[user_code] = {
                                'channel_names':[channel.name],
                            }
            
            #FIND THE DEFAULTERS NOTIFICATION KEYS
            users = list(unbalanced_users.keys())
            userset = User.objects.filter(user_code__in=users).values("notification_key",'name','user_code')
            
            messagePacket = []
            for usr in userset:
                udata = unbalanced_users[usr['user_code']]
                title = 'Pending Payments'
                sub_body = udata['channel_names'][0] + "'s paychannel still awaits your payment. Click to find channel and pay a part or whole"
                if len (udata['channel_names']) == 2:
                    sub_body = udata['channel_names'][0] + " and 1 other paychannel await your payments. Click to find channels and pay a part or whole"
                
                if len (udata['channel_names']) > 2:
                    sub_body = udata['channel_names'][0] + " and " +str(len(udata['channel_names']) - 1)+ " other paychannels await your payments. Click to find channels and pay a part or whole"

                if (usr['notification_key'] != 'nil'):
                    messagePacket.append({
                        "user_code":usr['user_code'],
                        "registration_token":usr['notification_key'],
                        "title":title,
                        "body":"Hi " + usr['name'].split(" ")[0] +", "+ sub_body,
                    })

            FcmAPI.send_notification(messagePacket)
            callresponse = {
                'passed': True,
                'response':200,
                'queryset':"retset"
            }
            return  HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def todayclasses_reminder(response): 
        if (response.method == "POST"):
            #SEND NOTIFICATION TO THE USER TO QUEUE NEW ATTENDANCE
            classes = Class.objects.all()
            days = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday']
            dt = datetime.now()
            dayindex = dt.weekday()            
            today = days[dayindex]
            
            for cl in classes:
                todaylist = cl['timetable']['tableset'][today]
                courses = []
                class_code = cl.class_code
                for cdata in todaylist:
                    courses.append(cdata['code'])     

                clist = ",".join(courses)
                FcmAPI.send_topic_notification({
                    "topic":class_code+"_today_classes",
                    "title":"Your class for today",
                    "body":"Find the classes slated for today:" + clist,
                })         
                
            callresponse = {
                'passed': True,
                'response':200,
                'queryset':"retset"
            }
            return  HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")


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
            callresponse['apiKey'] = GeneralAPI.getHash(user_code+"-"+str(time.time())+"-valid",'apiKey')

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
            callresponse['apiKey'] = GeneralAPI.getHash(u_data.user_code+"-"+str(time.time())+"-valid",'apiKey')

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

    def readApiKey(apikey):
        text = GeneralAPI.readHash(apikey, 'apiKey')
        if not text:
            return False
        parts = text.split('-')
        if len(parts) != 3:
            return False
        if parts[2] != 'valid':
            return False
        return parts[0]
        

    @csrf_exempt
    def add_document(self, response):
        if response.method == 'POST' and response.FILES.get('document'):
            callresponse = {
                'passed': False,
                'response':{},
                'error':{}
            }
            data =  json.loads(response.body.decode('utf-8'))
            user_code = UserAPI.readApiKey(data['apiKey'])
            if (not user_code):
                callresponse['Message'] = "Invalid access key"
                return HttpResponse(json.dumps(callresponse))
            
            uploaded_file = response.FILES['document']

            # Define the path inside the static folder
            current_time = int(time.time())
            upload_dir = os.path.join(settings.BASE_DIR, 'static', f'user_uploads/{user_code}/{current_time}')
            os.makedirs(upload_dir, exist_ok=True)
            
            file_path = os.path.join(upload_dir, uploaded_file.name)

            with open(file_path, 'wb+') as dest:
                for chunk in uploaded_file.chunks():
                    dest.write(chunk)
            
            user_upd = Uploads_reference.objects.filter(user=user_code).last()                
            user_upload_count = 0
            user_upload_sum_size = 0
            if (user_upd):                    
                user_upload_count = user_upd.user_upload_count
                user_upload_sum_size = user_upd.user_upload_sum_size

            upload_db = {
                "path": file_path, #CODE OF THE BOX IT IS CONTAINED
                "time": int(time.time()), #THIS IS THE SIMPLE IDENTIFIER WRITTEN ON THE BOX
                "user": user_code,
                "user_upload_count": user_upload_count + 1,
                "user_upload_sum_size":user_upload_sum_size + uploaded_file.size,
            }
            upload_db_sl = ModelSL(data={**upload_db}, model=Uploads_reference, extraverify={}) 
            upload_db_sl.is_valid() # MUST BE CALLED TO PROCEED
            upload_db_sl.save()

            file_url = f"https://openbox.bensons.africa/static/user_uploads/{user_code}/{current_time}/{uploaded_file.name}"
            
            callresponse['passed'] = True
            callresponse['response'] = {
                'upload_url':file_url
            }
            return HttpResponse(json.dumps(callresponse))
        return JsonResponse({'error': 'Invalid request'}, status=400)

    def get_recent_tasks(self, response):
        if (response.method == "POST"):
            callresponse = {
                'passed': False,
                'error':{}
            }
            data =  json.loads(response.body.decode('utf-8'))
            user_code = UserAPI.readApiKey(data['apiKey'])
            if (not user_code):
                callresponse['Message'] = "Invalid access key"
                return HttpResponse(json.dumps(callresponse))
            

            #CHECK USER'S VALIDIDTY
            _recent_tasks = Task.objects.filter(user_code=user_code).order_by('-time_in')[:4]
            if (not _recent_tasks):
                callresponse['passed'] = True
                callresponse['recent_tasks'] = []
                return HttpResponse(json.dumps(callresponse))
            
            recent_tasks = []
            for task in _recent_tasks:
                pub_task = {
                    "task_code":task.task_code,
                    "package_data":task.package_data,
                    "task_type":task.task_type,
                    "status":task.status,
                }
                box = Box.objects.filter(box_code=task.box_code)[0]
                pub_task['box'] = {
                    "name":box.name,
                    "description":box.description,
                    "address":box.address,
                }
                recent_tasks.append(pub_task)

            callresponse['passed'] = True 
            callresponse['recent_tasks'] = recent_tasks
            return HttpResponse(json.dumps(callresponse))
        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")


    
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

    def find_box_by_openquery(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))
            callresponse = {
                'passed': False,
                'response':{},
                'error':{}
            }
            
            boxes = Box.objects.filter(**data['query'])
            if (not boxes):
                callresponse['response'] = "Boxes not found with this query"
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

    def add_message(self, response):
        if (response.method == "POST"):

            data =  response.POST
            callresponse = {
                'passed': False,
                'response':400,
            }
            # callresponse['Message'] = "Invalid access key"
            # return HttpResponse(json.dumps(callresponse))
        
            user_code = UserAPI.readApiKey(data['apiKey'])
            if (not user_code):
                callresponse['Message'] = "Invalid access key"
                return HttpResponse(json.dumps(callresponse))
            
            task_code = "" #IN CASE A MESSAGE COMES IN FORM OF TASK REQUEST
            response_text = '',
            response_data = {}

            create_data = {}
            box_code = data['box_code']
            extension_type = data.get('extension_type') #dropbox, printbox #THIS IS THE CHAT TYPE
            chat_code = extension_type + "-" + box_code + "-" + user_code
            message_code = chat_code + "-" + str (time.time())

            create_data['user_code'] = user_code
            create_data['box_code'] = box_code
            create_data['chat_code'] = chat_code
            create_data['message_code'] = message_code
            create_data['message_side'] = data.get('message_side')
            create_data['message_type'] = data.get('message_type')
            create_data['text'] = data['text']
            create_data['document_url'] = data.get('document_url')
            create_data['attached_task'] = data.get('attached_task')
            # create_data['time'] = time.time()

            user = User.objects.filter(user_code=user_code)[0]
            box = Box.objects.filter(box_code=box_code)[0]
            
            if (data.get('attached_task') == 'print_doc'):                    

                #UPLOAD THE DOCUMENT FOR PRINTING
                uploaded_file = response.FILES['document_to_print']

                current_time = int(time.time())
                static_path = f'chat_uploads/{user_code}/{chat_code}/{current_time}'
                upload_dir = os.path.join(settings.BASE_DIR, 'static', static_path)
                os.makedirs(upload_dir, exist_ok=True)                
                file_path = os.path.join(upload_dir, uploaded_file.name)
                print (file_path)
                file_url = f"https://openbox.bensons.africa/static/{static_path}/{uploaded_file.name}"
                
                with open(file_path, 'wb+') as dest:
                    for chunk in uploaded_file.chunks():
                        dest.write(chunk)

                #UPDATE THE UPLOADS TRACKING TABLE
                user_upd = Uploads_reference.objects.filter(user=user_code).last()                
                user_upload_count = 0
                user_upload_sum_size = 0
                if (user_upd):
                    user_upload_count = user_upd.user_upload_count
                    user_upload_sum_size = user_upd.user_upload_sum_size

                upload_db = {
                    "path": file_path,
                    "time": int(time.time()),
                    "user": user_code,
                    "user_upload_count": user_upload_count + 1,
                    "user_upload_sum_size":user_upload_sum_size + uploaded_file.size,
                }
                upload_db_sl = ModelSL(data={**upload_db}, model=Uploads_reference, extraverify={}) 
                if not upload_db_sl.is_valid(): # MUST BE CALLED TO PROCEED
                    print ("Unable to add upload record")
                    print (upload_db_sl.cError())
                upload_db_sl.save()


                #BILL THE USER BEFORE INITIATING TASK  
                # number_of_pages = int(data['pages_range'][1]) - int(data['pages_range'][0]) 
                number_of_pages = 10

                print_price = number_of_pages * box.price_per_printpage
                if (data.get('print_type') == 'stored_printing'):
                    duration_price = box.storage_price_data[0][data['duration_key']]
                    print_price += duration_price

                if (user.cashbalance < print_price):
                    callresponse['response'] = 'Cash Out of Balance'
                    # return HttpResponse(json.dumps(callresponse))

                user.cashbalance -= print_price
                user.save()
                NotificationAPI.send({
                    "callback_url":'-',
                    "text":"Your account has been billed #"+str(print_price)+" for the printing service!",
                    "time":'date',
                    "category":"pay",
                    "owners":[user_code],
                    "otherdata":{}, #Any other data useful for that notification
                })
                
                #INSERT TRANSACTION 
                add_trans = TransactionAPI.add_transaction({
                    "payer_code":user_code,
                    "type":'in',
                    "amount":print_price,
                    "user_balance_to_date":user.cashbalance,
                    "item_code":"print_payment",
                    "description":"Payment for printing and storage"
                })
                if (not add_trans):
                    callresponse['passed'] = False,
                    return HttpResponse(json.dumps(callresponse))
                        

                #START A PRINTING TASK                
                pg_hole_id = "nil"
                pigeonholes = box.pigeonholes
                phindex = -1
                print(pigeonholes)
                for ph in pigeonholes:
                    print(ph)
                    if (ph['default_use'] != 'print_hole'):
                        continue
                    # if (ph['status'] != '0'): 
                    #     continue
                    pg_hole_id = ph['identifier']
                    phindex += 1
                    break
                
                
                if (pg_hole_id == 'nil'):
                    callresponse['response'] = 'No print hole is found in this box'
                    return HttpResponse(json.dumps(callresponse))

                access_code = random.randint(1000, 9999)
                task_data = {
                    "task_code": 'dummy',
                    "user_code":user_code,
                    "task_type" : "print", #COULD BE print, storage, movement
                    "access_code": access_code, #GENERATE A RANDOM 4-DIGIT CODE
                    "box_code": box_code, #THE CURRENT BOX PERFORMNG THIS TASK
                    "pg_id": pg_hole_id, #THE CURRENT SPECIFIC PG HOLE 
                    "package_data": {
                        "package_type":"print_doc",
                        "document_source_url":file_url,
                        "package_weight":"estimate_with_print_pages",
                        'task_history':[],
                        'holding_start':time.time(),
                        'holding_duration':data.get('duration_key')
                    }
                }
                task_sl = ModelSL(data={**task_data}, model=Task, extraverify={}) 
                if (not task_sl.is_valid()): # MUST BE CALLED TO PROCEED
                    print ("error occured")
                    print (task_sl.cError())
                ins_id = task_sl.save().__dict__['id']
                task_code = numberEncode(ins_id, 10)
                task_sl.validated_data['task_code'] = task_code
                task_sl.validated_data['package_data']['task_history'].append(task_code)
                task_sl.save()

                #UPDATE THE HOLE TO BUSY
                box.pigeonholes[phindex]['status'] = 1
                box.save()

                #NOTIFY THE BOX OF A PRINTING BY UPDATING BOX FIREBASE ENTRY
                #tasks/box_id:[task_codes]
                # db_data = FcmAPI.get_firedb_data('tasks/'+box_code)
                # upload_data = db_data[1]
                
                # upload_data.append(task_code)
                # ref = db_data[1]
                # ref.update(upload_data)

                db_data = FcmAPI.get_firedb_data('tasks/' + box_code)
                ref = db_data[0]
                upload_data = db_data[1] or []

                if isinstance(upload_data, list):
                    upload_data.append(task_code)
                    ref.set(upload_data)  # use set() for list data
                else:
                    ref.set([task_code]) 

                    

                NotificationAPI.send({
                    "callback_url":'-',
                    "text":f"Your printing has begun. Access your document at {box.name}, {pg_hole_id} with passcode {access_code}",
                    "time":'date',
                    "category":"access",
                    "owners":[user_code],
                    "otherdata":{}, #Any other data useful for that notification
                })

                response_text = "Your printing has started, your package is stashed for printing"
                response_data = {
                    'task_code':task_code,
                    'pg_hole_id':pg_hole_id,
                    'access_code':access_code
                }

            if (data.get('message_type') == 'store_package'):
                #BILL THE USER BEFORE INITIATING TASK  
                storage_price = box.storage_price_data[data['duration_key']]
                if (user.cashbalance < storage_price):
                    callresponse['response'] = 'Cash Out of Balance'
                    return HttpResponse(json.dumps(callresponse))

                user.cashbalance -= storage_price
                user.save()
                
                #INSERT TRANSACTION 
                add_trans = TransactionAPI.add_transaction({
                    "payer_code":user_code,
                    "type":'in',
                    "amount":storage_price,
                    "user_balance_to_date":user.cashbalance,
                    "item_code":"storage_payment",
                    "description":"Payment for storage"
                })
                if (not add_trans):
                    callresponse['passed'] = False,
                    return HttpResponse(json.dumps(callresponse))

                #START A STORAGE TASK                
                pg_hole_id = "nil"
                pigeonholes = box.pigeonholes
                phindex = -1
                for ph in pigeonholes:
                    #USE ANY AVAILABLE EVEN PRINT HOLES
                    # if (ph['default_use'] != 'storage_hole'):
                    #     continue
                    if (ph['status'] != '0'): 
                        continue
                    pg_hole_id = ph['identifier']
                    phindex += 1
                    break
                
                if (pg_hole_id == 'nil'):
                    callresponse['response'] = 'No print hole is found in this box'
                    return HttpResponse(json.dumps(callresponse))

                access_code = random.randint(1000, 9999)

                task_data = {
                    "task_code": 'dummy',
                    "task_type" : "storage", #COULD BE print, storage, movement
                    "access_code": access_code, #GENERATE A RANDOM 4-DIGIT CODE
                    "box_code": box_code, #THE CURRENT BOX PERFORMNG THIS TASK
                    "pg_code": pg_hole_id, #THE CURRENT SPECIFIC PG HOLE 
                    "status":'active',
                    "package_data": {
                        "package_type":"user_package",
                        "package_weight":"user_pack_weight",
                        'task_history':[],
                        'holding_start':time.time(),
                        'holding_duration':data['duration_key']
                    }
                }
                task_sl = ModelSL(data={**task_data}, model=Task, extraverify={}) 
                task_sl.is_valid() # MUST BE CALLED TO PROCEED
                ins_id = task_sl.save().__dict__['id']
                task_code = numberEncode(ins_id, 10)
                task_sl.validated_data['task_code'] = task_code
                task_sl.validated_data['package_data']['task_history'].append(task_code)
                task_sl.save()

                #UPDATE THE HOLE TO BUSY
                box.pigeonholes[phindex]['status'] = 1
                box.save()

                NotificationAPI.send({
                    "callback_url":'-',
                    "text":f"Your space is ready. Access space at {box.name}, {pg_hole_id} with passcode {access_code}",
                    "time":'date',
                    "category":"access",
                    "owners":[user_code],
                    "otherdata":{}, #Any other data useful for that notification
                })

                response_text = "The space is ready for use"
                response_data = {
                    'task_code':task_code,
                    'pg_hole_code':pg_hole_id,
                    'access_code':access_code
                }


            boxm_sl = ModelSL(data={**create_data}, model=Box_message, extraverify={}) 
            if (not boxm_sl.is_valid()): # MUST BE CALLED TO PROCEED
                print ("error occure")
                print(boxm_sl.cError())

            boxm_sl.save()
                       
            callresponse = {
                'passed': True,
                'response':200,
                'message_code':message_code,
                'response_text':response_text,
                'response_data':response_data,
            }

            return HttpResponse(json.dumps(callresponse))

        else:
            return HttpResponse("<div style='position: fixed; height: 100vh; width: 100vw; text-align:center; display: flex; justify-content: center; flex-direction: column; font-weight:bold>Page Not accessible<div>")

    def fetch_messages(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))

            user_code = response.session['user_data']['user_code']
            chat_code = data['chat_code']
            time_range = data.get('time_range') # [timestart, timeend]
            count = int (data.get('count', 10))
            
            searchquery = {
                "chat_code": chat_code,
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

    def get_remaining_messages(self, response):
        if (response.method == "POST"):
            data =  json.loads(response.body.decode('utf-8'))

            user_code = UserAPI.readApiKey(data['apiKey'])
            if (not user_code):
                callresponse['Message'] = "Invalid access key"
                return HttpResponse(json.dumps(callresponse))
            
            chat_code = data['chat_code']
            last_message_code = data.get('last_message_code') # [timestart, timeend]
            last_message_time = data.get('last_message_time') # Optional
            
            searchquery = {
                "chat_code": chat_code,
                "message_code": last_message_code,
            }

            # Check if time_range is provided (it should be a tuple or list of 2 values: start time, end time)
            if not last_message_time:
                messages = Box_message.objects.filter(**searchquery)
                if (messages):
                    last_message_time = messages[0].time
                else:
                    last_message_time = 0

            searchquery = {
                "chat_code": chat_code,
                "time__range":(last_message_time, time.time())
            }

            # Query the database with the searchquery dictionary
            messages = Box_message.objects.filter(**searchquery).order_by('time')

            # Limit the number of messages if `count` is provided
            if data.get('last_message_time'):
                messages = messages[:data.get('last_message_time')]

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

    @csrf_exempt
    def upload_boxes(self, response):
        if response.method == 'POST' and response.FILES.get('document'):
            box = Box.objects.filter(box_code='BOX005')[0]
            print (box.name)
            return JsonResponse({'message': 'Boxes imported successfully'}, status=201)

            try:
                file = response.FILES['document']
                df = pd.read_excel(file)

                for _, row in df.iterrows():
                    Box.objects.create(
                        box_code=row['box_code'],
                        name=row['name'],
                        address=row['address'],
                        description=row['description'],
                        box_type=row['box_type'],
                        create_time=row['create_time'],
                        admins=ast.literal_eval(row['admins']),
                        storage_price_data=ast.literal_eval(row['storage_price_data']),
                        price_per_printpage=row['price_per_printpage'],
                        pigeonholes=ast.literal_eval(row['pigeonholes']),
                        state=row['state'],
                        city=row['city'],
                        street=row['street'],
                        latitude=row['latitude'],
                        longitude=row['longitude'],
                        status=row['status'],
                    )

                print ("Success")

                return JsonResponse({'message': 'Boxes imported successfully'}, status=201)
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=400)

        return JsonResponse({'error': 'No file uploaded'}, status=400)



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

    def add_transaction(transaction_data):
        '''
            {
                "payer_code":payer,
                "type":_type,
                "amount":12,
                "item_code":"print_payment",
                "description":"Payment for printing and storage",
                "user_balance_to_date":user.cashbalance,

            }
        '''
        
        try:
            recent_transact = Transaction.objects.latest("id")
        except Exception as e:
            recent_transact = None

        balance2date = 0
        if (recent_transact):
            balance2date = recent_transact.system_balance_to_date

        if (transaction_data['type'] == 'in'):
            b2d = balance2date+transaction_data['amount']
        if (transaction_data['type'] == 'out'):
            b2d = balance2date - transaction_data['amount']
            
        transaction_data = {
            **transaction_data,
            "transact_code":"__",
            "system_balance_to_date":b2d,
            "date":datetime.now().isoformat(),
        }
        sl = ModelSL(data=transaction_data, model=Transaction, extraverify={})
        if (sl.is_valid()):
            ins_id = sl.save().__dict__['id']
            sl.validated_data['transact_code'] = numberEncode(ins_id, 10)
            sl.save()
            return True
        else:
            return False

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
            data =  json.loads(response.body.decode('utf-8'))
            user_code = UserAPI.readApiKey(data['apiKey'])
            if (not user_code):
                callresponse['Message'] = "Invalid access key"
                return HttpResponse(json.dumps(callresponse))
            
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
            user_code = UserAPI.readApiKey(data['apiKey'])
            if (not user_code):
                callresponse['Message'] = "Invalid access key"
                return HttpResponse(json.dumps(callresponse))

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
            user_code = UserAPI.readApiKey(data['apiKey'])
            if (not user_code):
                callresponse['Message'] = "Invalid access key"
                return HttpResponse(json.dumps(callresponse))
            
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
            user_code = UserAPI.readApiKey(data['apiKey'])
            if (not user_code):
                callresponse['Message'] = "Invalid access key"
                return HttpResponse(json.dumps(callresponse))

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
        data =  json.loads(response.body.decode('utf-8'))
        user_code = UserAPI.readApiKey(data['apiKey'])
        if (not user_code):
            callresponse['Message'] = "Invalid access key"
            return HttpResponse(json.dumps(callresponse))

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
        dataset['time']= int (time.time())

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
            User.objects.filter(Q(user_code__in=userlist)).update(unread_notice_count=F('unread_notice_count')+1)

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
