from bs4 import BeautifulSoup
import base64
import urllib.parse
from ..models import User


def inAllowed(text, allowed):
    allowed = str(allowed)
    if allowed == 'def':
        allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890_@. "
    ret = True
    for x in text:
        if (not allowed.__contains__(x)):
            ret = False
            break
    if allowed == 'idef':
        ret = True
    return ret

def validateEntry(retdata, entry, name, minlen, maxlen, allowed):

    if (entry is not None):
        if (not inAllowed(entry, allowed)):
            retdata['passed'] = False
            retdata.get("error")[name.lower()]=(name + " contains characters that are not allowed")
        else:
            if (len(entry) > maxlen):
                retdata['passed'] = False
                retdata.get("error")[name.lower()]=(name + " contains too many characters. Max of " + str(maxlen) + " is allowed")
                
            if (len(entry) < minlen):
                retdata['passed'] = False
                retdata.get("error")[name.lower()]=(name + " contains too few characters. Min of " + str(minlen) + " is allowed")
     
    else:
        retdata['error'] = {
            name.lower(): (name + " is not set")
        }

    return entry
    
def validatenum(retdata, num, name, minval, maxval):
    if (entry is None):
        retdata['passed'] = False
        retdata.get("error")[name.lower()]=(name + " is not set")
    else:
        if (type(num)==float or type(num)==int):
            if (num > minval):
                retdata['passed'] = False
                retdata.get("error")[name.lower()]=(name + " can not be greater than " + maxval)
            if (num < minval):
                retdata['passed'] = False
                retdata.get("error")[name.lower()]=(name + " can not be lesser than " + minval)
        else:
            retdata['passed'] = False
            retdata.get("error")[name.lower()]=(name + " is not a valid number")

    return num

def validateArray(retdata, arr, name, minlen, maxlen):
    if (entry is None):
        retdata['passed'] = False
        retdata.get("error")[name.lower()]=(name + " is not set")
    else:
        if not type(arr) == list:
            retdata['passed'] = False
            retdata.get("error")[name.lower()]=(name + " must be an array")
        else:
            if (len(arr) < minlen):
                retdata['passed'] = False
                retdata.get("error")[name.lower()]=(name + " can only contain a minimum of " + minlen + " entries")
            if (len(arr) > maxlen):
                retdata['passed'] = False
                retdata.get("error")[name.lower()]=(name + " can only contain a maximum of " + maxlen + " entries")

    return arr

def validateDict(retdata, arr, name, minlen, maxlen):
    if (entry is None):
        retdata['passed'] = False
        retdata.get("error")[name.lower()]=(name + " is not set")
    else:
        if not type(arr) == dict:
            retdata['passed'] = False
            retdata.get("error")[name.lower()]=(name + " must be an JSON")
        else:
            if (len(arr) < minlen):
                retdata['passed'] = False
                retdata.get("error")[name.lower()]=(name + " can only contain a minimum of " + minlen + " entries")
            if (len(arr) > maxlen):
                retdata['passed'] = False
                retdata.get("error")[name.lower()]=(name + " can only contain a maximum of " + maxlen + " entries")
    return arr

def numberEncode(code, encNum, spc=False):
    if (not encNum):
        encNum = len(code)
    code = str(code).zfill(encNum)   #Pad on the left with zeros
    Res = 'ZgBoFklNOaJKLM5XYh12pqr6wQRSTdefijAPbcU4mnVW0stuv78xyzGCDE3HI9'
    if (spc):
        Res = 'ZgBoFklNOaJKLM5XYh12pqr6wQRSTdefijAPbcU4mnVW0stuv78xyzGCDE3HI9_'
    if (spc == 'mail'):
        Res = '.@ZgBoFklNOaJKLM5XYh12pqr6wQRSTdefijAPbcU4mnVW0stuv78xyzGCDE3HI9_'
    
    
    tlenght = len(Res)
    rtl = ''
    cdLen = len(code)
    former = 0
    for i in range(cdLen):
        ind = cdLen - i - 1
        el = code[ind]
        k = (Res.index(el) + encNum + ind + former) % tlenght
        rtl += Res[k]
        former = k
    return rtl

def numberDecode(code, encNum, spc=False):       
    if (not encNum):
        encNum = len(code)           
    Res='ZgBoFklNOaJKLM5XYh12pqr6wQRSTdefijAPbcU4mnVW0stuv78xyzGCDE3HI9'
    if (spc):
        Res = 'ZgBoFklNOaJKLM5XYh12pqr6wQRSTdefijAPbcU4mnVW0stuv78xyzGCDE3HI9_'
    if (spc == 'mail'):
        Res = '.@ZgBoFklNOaJKLM5XYh12pqr6wQRSTdefijAPbcU4mnVW0stuv78xyzGCDE3HI9_'
    tlenght = len(Res)
    cdLen = len(code)
    rtl = ''
    former = 0
    for i in range(cdLen):
        el = code[i]
        ind = cdLen - i - 1
        rk = Res.index(el)
        k =  (rk - encNum - ind - former + tlenght) % tlenght
        rtl =  Res[k]+rtl
        former = rk
    return rtl

def numberEncode_upper(code, encNum, justNum=False):
    
    code = str(code).zfill(encNum)   #Pad on the left with zeros
    
    Res = 'PQV34O6ZW12B78DESG9F50AKCRTULMNXHJY'
    if justNum:
        Res = '2367519840'
    tlenght = len(Res)
    rtl = ''
    cdLen = len(code)
    former = 0
    for i in range(cdLen):
        ind = cdLen - i - 1
        el = code[ind]
        k = (Res.index(el) + encNum + ind + former) % tlenght
        rtl += Res[k]
        former = k
    return rtl

def isloggedin(response):

    return response.session.get('user') is not None

def sanitize_html(value, mtype="none"):

    soup = BeautifulSoup(value)
        
    VALID_TAGS = ['strong', 'em', 'p', 'ul', 'li', 'br']
    if mtype == "none":
        VALID_TAGS = []

    for tag in soup.findAll(True):
        if tag.name not in VALID_TAGS:
            tag.hidden = True

    ret = str(soup.renderContents().decode())

    print (ret)
    if ret == "":
        ret = "..."
    return ret

        
def readurl(url):
    top = urllib.parse.parse_qs(url) 
    ret = {}
    for k in top:
        if (len(k.split("?")) == 2):
            ret[k.split("?")[1]] = top[k][0]
            continue
        ret[k] = top[k][0]

    return ret