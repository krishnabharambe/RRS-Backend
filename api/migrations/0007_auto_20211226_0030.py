# Generated by Django 3.2 on 2021-12-25 19:00

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_auto_20211225_2357'),
    ]

    operations = [
        migrations.AlterField(
            model_name='r_requests',
            name='ServiceID',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='api.m_subservices'),
        ),
        migrations.AlterField(
            model_name='r_requests',
            name='UserId',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL),
        ),
    ]
