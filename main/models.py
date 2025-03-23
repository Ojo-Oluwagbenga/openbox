from django.db import models

# Create your models here.
class User(models.Model):
    name = models.CharField(max_length=100)
    email = models.CharField(max_length=100)  
    password = models.CharField(max_length=100) 
    join_time = models.IntegerField(default=0)
    
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