from django.db import models

# Create your models here.
from django.db import models


class User(models.Model):
    username = models.CharField(max_length=50)
    public_key = models.CharField(max_length=200)
    is_active = models.BooleanField(default=True)

    class Meta:
        app_label = "web3_auth"

    def __str__(self):
        if self.username:
            return self.username
        else:
            return "N/A"

