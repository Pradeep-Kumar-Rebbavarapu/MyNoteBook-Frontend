# Generated by Django 4.0.4 on 2022-05-08 13:01

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Note',
            fields=[
                ('note_id', models.AutoField(primary_key=True, serialize=False)),
                ('title', models.CharField(blank=True, default=None, max_length=225, null=True)),
                ('desc', models.CharField(blank=True, default=None, max_length=1000, null=True)),
                ('tag', models.CharField(blank=True, default=None, max_length=1000, null=True)),
                ('datestamp', models.CharField(default=None, max_length=225)),
                ('timestamp', models.CharField(default=None, max_length=225)),
                ('user', models.ForeignKey(blank=True, default=None, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='user_id', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]