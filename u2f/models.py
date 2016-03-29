from __future__ import unicode_literals

from django.contrib.auth.models import User

from django.conf import settings
from django.db import models

# Append to the users object
class U2FKey(models.Model):
    user = models.ForeignKey(User, related_name='u2f_keys')
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True)

    public_key = models.TextField()
    key_handle = models.TextField()
    app_id = models.TextField()

    def to_json(self):
        return {
            'publicKey': self.public_key,
            'keyHandle': self.key_handle,
            'appId': self.app_id,
        }
