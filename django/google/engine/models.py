from django.db import models

# Create your models here.
class Query(models.Model):
	query = models.CharField(max_length = 500)
	hits = models.IntegerField(default = 1)
	user_id = models.IntegerField(default=0)

	def __str__(self):
		return self.query