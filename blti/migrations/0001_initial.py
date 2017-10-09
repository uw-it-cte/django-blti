# -*- coding: utf-8 -*-
# Generated by Django 1.10.7 on 2017-10-09 17:45
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='BLTIKeyStore',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('consumer_key', models.CharField(max_length=80, unique=True)),
                ('shared_secret', models.CharField(max_length=80)),
                ('added_date', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
