# Generated by Django 4.0.8 on 2022-12-28 14:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('discord_auth', '0003_token_scopes'),
    ]

    operations = [
        migrations.AlterField(
            model_name='token',
            name='ttl',
            field=models.DurationField(editable=False, help_text='The number of seconds that the token is valid for.'),
        ),
    ]
