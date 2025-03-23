from . import api
from django.http import HttpResponse
import json
from django.contrib.sessions.models import Session
from django.views.decorators.csrf import csrf_exempt


class Manager:
    @csrf_exempt
    def manager(response, apiclass, apimethod):

        class_ = getattr(api, apiclass.capitalize() + "API")
        return getattr(class_, apimethod)(class_, response)

        try:
            class_ = getattr(api, apiclass.capitalize() + "API")
            return getattr(class_, apimethod)(class_, response)
        except Exception as e:
            ret = {
                'response':201,
                'errorcode':201,
                "Message": str(e)
            }
            return HttpResponse(json.dumps(ret))
