from django.contrib import admin

# Register your models here.
from .models import product,Pricing

admin.site.register(product)
admin.site.register(Pricing)
