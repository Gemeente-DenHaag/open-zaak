.. _installation_reference_cli:

Command Line Interface (CLI)
============================

Open Zaak ships with a command line interface accessible inside of the containers.

To get more information about a command, you can run:

.. code-block:: bash

    $ python src/manage.py <command> --help

Available commands
------------------

``createinitialsuperuser``
    Creates an initial superuser with the specified username and e-mail address.

    The password can be provided upfront with the ``--password`` CLI argument, or by
    using the ``DJANGO_SUPERUSER_PASSWORD`` environment variable. Additionally,
    with ``--generate-password`` a password can be generated and e-mailed to the
    specified e-mail address. Note that this requires your e-mail configuration to be
    set up correctly (any of the ``EMAIL_*`` envvars)!

``setup_configuration``
    A CLI alternative to the point-and-click configuration in the admin interface.

``send_test_notification``
    After configuring the Notificaties API, send a test nofification to verify the
    setup.

``register_kanaal``
    Registers a notifications channel with the notifications API if it doesn't exist
    yet. Channels must exist before Open Zaak can publish notifications to them.
