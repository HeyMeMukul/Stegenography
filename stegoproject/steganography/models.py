from django.db import models

class StegoImage(models.Model):
    image = models.ImageField(upload_to='images/')
    hidden_text = models.TextField()
    encryption_key = models.CharField(max_length=50)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Image {self.id} - Uploaded at {self.uploaded_at}"
