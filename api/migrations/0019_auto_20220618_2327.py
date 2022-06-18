# Generated by Django 3.2 on 2022-06-18 17:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0018_auto_20220530_2014'),
    ]

    operations = [
        migrations.AlterField(
            model_name='offers',
            name='Status',
            field=models.CharField(choices=[('Active', 'Active'), ('Pending', 'Pending'), ('Complete', 'Complete'), ('Archived', 'Archived'), ('Cancelled', 'Cancelled'), ('OpenPool', 'OpenPool')], default='Active', max_length=100),
        ),
        migrations.AlterField(
            model_name='r_requests',
            name='Status',
            field=models.CharField(choices=[('Active', 'Active'), ('Pending', 'Pending'), ('Complete', 'Complete'), ('Archived', 'Archived'), ('Cancelled', 'Cancelled'), ('OpenPool', 'OpenPool')], default='Active', max_length=100),
        ),
        migrations.AlterField(
            model_name='requestassign',
            name='bookingStatus',
            field=models.CharField(choices=[('Active', 'Active'), ('Pending', 'Pending'), ('Complete', 'Complete'), ('Archived', 'Archived'), ('Cancelled', 'Cancelled'), ('OpenPool', 'OpenPool')], default='Active', max_length=100),
        ),
    ]
