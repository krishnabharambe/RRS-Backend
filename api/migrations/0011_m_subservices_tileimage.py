# Generated by Django 3.2 on 2022-01-18 08:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_offers'),
    ]

    operations = [
        migrations.AddField(
            model_name='m_subservices',
            name='TileImage',
            field=models.ImageField(default=1, upload_to='Tileimages/'),
            preserve_default=False,
        ),
    ]
