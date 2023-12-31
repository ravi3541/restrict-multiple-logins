# Generated by Django 4.2.1 on 2023-06-24 10:16

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("token_blacklist", "0012_alter_outstandingtoken_user"),
        ("users", "0003_blacklistedtoken"),
    ]

    operations = [
        migrations.CreateModel(
            name="CustomTokenBlacklistOutstanding",
            fields=[
                (
                    "outstandingtoken_ptr",
                    models.OneToOneField(
                        auto_created=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        parent_link=True,
                        primary_key=True,
                        serialize=False,
                        to="token_blacklist.outstandingtoken",
                    ),
                ),
                (
                    "user_device",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="users.userdevice",
                    ),
                ),
            ],
            bases=("token_blacklist.outstandingtoken",),
        ),
    ]
