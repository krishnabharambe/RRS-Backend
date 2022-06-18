# Generated by Django 3.2 on 2022-05-30 14:44

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0017_alter_profile_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='requestassign',
            name='booking',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='bookingDetails', to='api.r_requests'),
        ),
        migrations.AlterField(
            model_name='requestassign',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='staffDetails', to=settings.AUTH_USER_MODEL),
        ),
    ]