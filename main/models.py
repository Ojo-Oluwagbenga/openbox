from django.db import models
from django.contrib.postgres.fields import ArrayField


# Create your models here.
class User(models.Model):
    name = models.CharField(max_length=100)
    email = models.CharField(max_length=100)  
    password = models.CharField(max_length=100) 
    phone_number = models.CharField(max_length=100) 
    join_time = models.IntegerField(default=0)
    cashbalance = models.FloatField(default=0)
    
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
    price_per_printpage = models.CharField(default=0, max_length=100)
    pigeonholes = ArrayField(models.CharField(max_length=100), blank=True)

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
    create_time = models.CharField(default=0, max_length=100)
    price_per_hr = models.CharField(default=0, max_length=100)

class Box_message(models.Model):
    message_code = models.CharField(max_length=100) 
    user_code = models.CharField(max_length=100)
    box_code = models.CharField(max_length=100) 
    message_side = models.CharField(max_length=50) # user or computer
    message_type = models.CharField(max_length=50) # different keys should be used here for different display
    text = models.CharField(max_length=600) 
    document_url = models.CharField(max_length=100) 
    time = models.CharField(max_length=100) 
    otherdata = models.JSONField(null=True)


class Notification(models.Model):
    noti_code = models.CharField(max_length=50)
    callback_url = models.CharField(max_length=200)
    text = models.CharField(max_length=200)
    time = models.CharField(max_length=100)
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
    type = models.CharField(max_length=50) #out for withdrawal, in for payment
    item_code = models.CharField(max_length=50) #WALLLET, BOX PAYMENT
    balance_to_date = models.FloatField() #This is only added on payment received
    amount = models.FloatField()
    date = models.CharField(max_length=200)
    data = models.JSONField(null=True) #This contains other important data to this like withdrawal data


class Task(models.Model):
    task_code = models.CharField(max_length=50)
    task_type = models.CharField(max_length=50) #COULD BE printing, storage, movement
    access_code = models.CharField(max_length=50) #CURRENT BOX ACCESS DIGIT FOR THIS TASK
    box_code = models.CharField(max_length=50) #THE CURRENT BOX PERFORMNG THIS TASK
    pg_code = models.CharField(max_length=50) #THE CURRENT SPECIFIC PG HOLE 
    status = models.CharField(max_length=50, default="waiting") #COULD BE waiting, active, completed, terminated
    time_in = models.CharField(max_length=50) 
    time_start = models.CharField(max_length=50) 
    time_completed = models.CharField(max_length=50) 
    time_terminated = models.CharField(max_length=50) 
    package_data = models.JSONField(null=True) 
    '''
        {
            package_type:"print_doc", "user_package",
            document_source_url:'https://kkk/ups/jk.jpg'
            package_weight:"",
            task_history:[task_code1, task2] //THIS IS FOR CASES WHEN IT IS MOVED OR SO.
        }
    '''
