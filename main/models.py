from django.db import models
from django.contrib.postgres.fields import ArrayField
import time

def current_unix_time():
    return int(time.time())

# Create your models here.
class User(models.Model):
    name = models.CharField(max_length=100)
    email = models.CharField(max_length=100)  
    password = models.CharField(max_length=100) 
    phone_number = models.CharField(max_length=100) 
    join_time = models.IntegerField(default=0)
    cashbalance = models.FloatField(default=0)
    unread_notice_count = models.IntegerField(default=0)

    
    user_code = models.CharField(max_length=50)   
    user_type = models.CharField(max_length=50) #supervisor or supervisee
    draft = models.JSONField(null=True)


class UserTemp(models.Model):
    name = models.CharField(max_length=100)
    email = models.CharField(max_length=100)  
    password = models.CharField(max_length=100) 
    join_time = models.IntegerField(default=0)

    user_code = models.CharField(max_length=50)   
    user_type = models.CharField(max_length=50) #supervisor or supervisee

class Box(models.Model):
    box_code = models.CharField(max_length=100) 
    name = models.CharField(max_length=200)
    address = models.CharField(max_length=200)  
    description = models.CharField(max_length=700) 
    box_type = models.CharField(max_length=100) 
    create_time = models.CharField(default=0, max_length=100)
    admins = ArrayField(models.CharField(max_length=100), blank=True)
    storage_price_data = ArrayField(models.JSONField(null=True) , blank=True)
    '''
        storage_price_data takes the form 
        "6hrs":20,
        "1day":30,
        "3days":70,
        "1week":90,
        "2weeks":90,
        "1month":90,
        "3months":90,
        "6months":90,
    '''
    price_per_printpage = models.FloatField(default=0)
    pigeonholes = ArrayField(models.JSONField(null=True) , blank=True)

    '''
        [
            {
                identifier:"IDF", #THIS IS THE SIMPLE IDENTIFIER WRITTEN ON THE BOX
                status:"",
                time:"", //ESTIMATED TIME OF USE
                price_per_hr:"",
                default_use:"", #print_hole or drop_hole
                dimension: {
                    height:"",
                    width:''
                    length:"",
                },
            },
        ]
    '''

    #TO FIND THE BOX
    state = models.CharField(default="", max_length=100)
    city = models.CharField(default="", max_length=100)
    street = models.CharField(default="", max_length=100)
    latitude = models.FloatField(default=0)
    longitude = models.FloatField(default=0)
    status = models.CharField(default="0", max_length=100) #THIS CAN BE 1 FOR ACTIVE, 0 FOR INACTIVE

class Pigeonhole(models.Model):
    box_code = models.CharField(max_length=100) #CODE OF THE BOX IT IS CONTAINED
    box_id = models.CharField(max_length=100) #THIS IS THE SIMPLE IDENTIFIER WRITTEN ON THE BOX
    pg_code = models.CharField(max_length=100) #THIS IS ABSOLUTE IDENTIFIER ON THE SYSTEM
    status = models.CharField(max_length=100) #1 FOR BUSY AND 0 FOR AVAILABLE    
    time = models.BigIntegerField(default=current_unix_time) #ESTIMATED TIME OF USE
    price_per_hr = models.CharField(default=0, max_length=100)
    default_use = models.CharField(max_length=100) #print_hole or drop_hole
    dimension = models.JSONField(null=True) 
    '''
        {
            height:"",
            width:''
            length:"",
        }
    '''

class Task(models.Model):
    task_code = models.CharField(max_length=50)
    task_type = models.CharField(max_length=50) #COULD BE print, storage, movement
    access_code = models.CharField(max_length=50) #CURRENT BOX ACCESS DIGIT FOR THIS TASK
    box_code = models.CharField(max_length=50) #THE CURRENT BOX PERFORMNG THIS TASK
    user_code = models.CharField(max_length=50) #THE USER OWNING THIS TASK
    pg_id = models.CharField(max_length=50) #THE SIMPLE IDENTIFIER CURRENT SPECIFIC PG HOLE ON THE SELECTED BOX 
    status = models.CharField(max_length=50, default="waiting") #COULD BE waiting, active, completed, terminated
    time_in = models.BigIntegerField(default=current_unix_time) 
    time_start = models.BigIntegerField(default=0) 
    time_completed = models.BigIntegerField(default=0) 
    time_terminated = models.BigIntegerField(default=0) 
    package_data = models.JSONField(null=True) 
    '''
        {
            package_type:"print_doc", "user_package",
            document_source_url:'https://kkk/ups/jk.jpg'
            holding_duration:"",
            holding_start:"",
            package_weight:"",
            task_history:[task_code1, task2] //THIS IS FOR CASES WHEN IT IS MOVED OR SO.
        }
    '''

class Task_Notice(models.Model):
    box_code = models.CharField(max_length=50)
    has_job = models.BooleanField() #True MEANS HAVING A JOB, False IS OTHERWISE
    task_codes = ArrayField(models.CharField(max_length=50))
    upd_code = models.BigIntegerField(default=0) #THIS IS TIME IN SEC

class Box_message(models.Model):
    message_code = models.CharField(max_length=100) 
    chat_code = models.CharField(max_length=100) #THIS IS CAN BE ext-boxcode(print-boxcode, drop-boxcode) 
    user_code = models.CharField(max_length=100)
    box_code = models.CharField(max_length=100) 
    message_side = models.CharField(max_length=50, default='system') # user or system
    message_type = models.CharField(max_length=50, default="ordinary") # different keys should be used here for different display E.G document_display, ordinary, transaction_success, e.t.c
    attached_task = models.CharField(max_length=50, default="none") # can be print, storage e.t.c
    text = models.CharField(max_length=600) 
    document_url = models.CharField(max_length=200, default="none") 
    document_address_code = models.CharField(max_length=100, default="none") 
    time = models.BigIntegerField(default=current_unix_time)
    otherdata = models.JSONField(null=True)


class Notification(models.Model):
    noti_code = models.CharField(max_length=50)
    callback_url = models.CharField(max_length=200)
    text = models.CharField(max_length=200)
    time = models.BigIntegerField(default=current_unix_time)
    category = models.CharField(max_length=50)
    owners = ArrayField(models.CharField(max_length=50))
    otherdata = models.JSONField(null=True)


#This is a temporary place to initiate a transaction.
class PayTransact(models.Model):
    reference_code = models.CharField(max_length=100)
    user_code = models.CharField(max_length=100)
    date = models.CharField(max_length=100, default="-")
    item_code = models.CharField(max_length=100, default="-")#This is the code of the item user are paying for

#This holds all major transactions
class Transaction(models.Model):
    transact_code = models.CharField(max_length=50)
    payer_code = models.CharField(max_length=50)
    description = models.CharField(max_length=300)
    type = models.CharField(max_length=50) #out for withdrawal, in for payment
    item_code = models.CharField(max_length=50) #WALLLET, BOX PAYMENT
    system_balance_to_date = models.FloatField() #This is only added on payment received
    user_balance_to_date = models.FloatField() #This is only added on payment received
    amount = models.FloatField()
    time = models.BigIntegerField(default=current_unix_time)
    data = models.JSONField(null=True) #This contains other important data to this like withdrawal data

class Uploads_reference(models.Model):
    address_code = models.CharField(max_length=100) 
    path = models.CharField(max_length=500) #CODE OF THE BOX IT IS CONTAINED
    time = models.FloatField(default=0) #THIS IS THE SIMPLE IDENTIFIER WRITTEN ON THE BOX
    user = models.CharField(max_length=100) 
    file_name = models.CharField(max_length=100) 
    file_size = models.CharField(max_length=100) 
    user_upload_count = models.IntegerField(default=0) 
    user_upload_sum_size = models.FloatField(default=0)

