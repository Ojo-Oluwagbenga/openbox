from django.shortcuts import render
from django.http import HttpResponse
from django.views import View
import json
import time
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
            user_sl = ModelSL(data={**data}, model=User, extraverify={})

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
