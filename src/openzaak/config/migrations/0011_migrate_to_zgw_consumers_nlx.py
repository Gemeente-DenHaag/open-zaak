# SPDX-License-Identifier: EUPL-1.2
# Copyright (C) 2021 Dimpact
# Generated by Django 2.2.25 on 2021-12-22 08:50

from django.db import migrations


def copy_config_to_zgw_consumers(apps, _):
    OZNLXConfig = apps.get_model("config", "NLXConfig")
    ZGWCNXLConfig = apps.get_model("zgw_consumers", "NLXConfig")

    oz_config = OZNLXConfig.objects.first()
    zgw_c_config = ZGWCNXLConfig.objects.first()
    if oz_config is None or zgw_c_config is None:
        return

    zgw_c_config.directory = oz_config.directory
    zgw_c_config.outway = oz_config.outway
    zgw_c_config.save()


def copy_config_from_zgw_consumers(apps, _):
    OZNLXConfig = apps.get_model("config", "NLXConfig")
    ZGWCNXLConfig = apps.get_model("zgw_consumers", "NLXConfig")

    oz_config = OZNLXConfig.objects.first()
    zgw_c_config = ZGWCNXLConfig.objects.first()
    if oz_config is None or zgw_c_config is None:
        return

    oz_config.directory = zgw_c_config.directory
    oz_config.outway = zgw_c_config.outway
    oz_config.save()


class Migration(migrations.Migration):

    dependencies = [
        ("config", "0010_auto_20210323_1613"),
        ("zgw_consumers", "0010_nlxconfig"),
    ]

    operations = [
        migrations.RunPython(
            copy_config_to_zgw_consumers, copy_config_from_zgw_consumers
        ),
    ]