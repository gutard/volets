from django.core.validators import MaxValueValidator
from django.db import models


class Group(models.Model):
    address = models.PositiveIntegerField(validators=MaxValueValidator(0xffff))


class Device(models.Model):
    address = models.PositiveIntegerField(validators=MaxValueValidator(0xffff))
    name = models.CharField(max_length=100)
    groups = models.ManyToManyField(related_name='devices')
