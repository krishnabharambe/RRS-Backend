# Generated by Django 3.2 on 2021-12-23 21:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0004_r_requests'),
    ]

    operations = [
        migrations.AddField(
            model_name='r_requests',
            name='Status',
            field=models.CharField(choices=[('Active', 'Active'), ('Pending', 'Pending'), ('Complete', 'Complete'), ('Archived', 'Archived'), ('Cancelled', 'Cancelled')], default='Active', max_length=100),
        ),
    ]
