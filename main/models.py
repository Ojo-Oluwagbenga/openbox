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
    '''
        {
            supervisor_id:sid,
            supervisor_name:sname
            supervisee_id:seid
            supervisee_name:sename
            meeting_date:m_date (select_from_dropdown)
            meeting_summary:m_summary
            submission_time:stime
        }
    '''

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

class Box_chat(models.Model):
    chat_code = models.CharField(max_length=100) 
    user_code = models.CharField(max_length=100)
    box_code = models.CharField(max_length=100) 
    message_record = models.JSONField(null=True)


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
class Transactions(models.Model):
    transact_code = models.CharField(max_length=50)
    payer_code = models.CharField(max_length=50)
    type = models.CharField(max_length=50) #out for withdrawal, in for payment
    item_code = models.CharField(max_length=50) #WALLLET, BOX PAYMENT
    balance_to_date = models.FloatField() #This is only added on payment received
    amount = models.FloatField()
    date = models.CharField(max_length=200)
    data = models.JSONField(null=True) #This contains other important data to this like withdrawal data
