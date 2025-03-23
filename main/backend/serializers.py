from rest_framework import serializers
from ..models import *
from .utils import *
import json
from rest_framework.parsers import JSONParser
from rest_framework.renderers import JSONRenderer



class ModelSL(serializers.ModelSerializer):
    class Meta:
        # The values below are the test values
        model = User
        fields = '__all__'

    callresponse = {
        'passed': True,
        'response':{},
        'error':{}
    }
    
       
    def __init__(self, **kwargs):
        self.callresponse = {
            'passed': True,
            'response':{},
            'error':{}
        }

        if (kwargs.get('selection') is not None):
            self.Meta.fields = kwargs['selection']
        self.Meta.model = kwargs['model']
        self.extraverify = kwargs['extraverify']
        
        super().__init__(data=kwargs.get("data"))
        
    def validate(self, data):
        for k,v in self.extraverify.items():
            validateEntry(self.callresponse, data.get(k), k.capitalize(), v[0], v[1], v[2])
        return data

    def cUpdate(self, colid, valData):       
        model = (self.Meta.model.objects.filter(itemcode=colid))
        if model.exists():
            model = model[0]
            for key, val in valData.items():
                setattr(model, key, val)
            model.save()
            self.callresponse['passed'] = True
            self.callresponse['response']['itemcode'] = model.itemcode
        else:
            self.callresponse['passed'] = False
            self.callresponse['error']['itemcode'] = "Item Code does not exist"

        return self.callresponse

    def cError(self):
        print("\n\n\n", self.errors)
        errs = json.loads(JSONRenderer().render(self.errors))
        self.callresponse['passed'] = False
        for key, value in errs.items():
            print(value)
            if (value):
                self.callresponse['error'][key] = value
            else:
                self.callresponse['error'][key] = value[0]
                
        return self.callresponse
