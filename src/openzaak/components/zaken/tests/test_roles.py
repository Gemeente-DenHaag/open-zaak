# SPDX-License-Identifier: EUPL-1.2
# Copyright (C) 2022 Dimpact
"""
Guarantee that the proper authorization machinery is in place.
"""
from django.test import override_settings, tag

import requests_mock
from rest_framework import status
from rest_framework.test import APITestCase
from vng_api_common.authorizations.models import Autorisatie
from vng_api_common.constants import ComponentTypes, VertrouwelijkheidsAanduiding
from vng_api_common.tests import reverse

from openzaak.components.autorisaties.tests.factories import RoleFactory
from openzaak.components.catalogi.tests.factories import ZaakTypeFactory
from openzaak.utils.tests import JWTAuthMixin, generate_jwt_auth

from ..api.scopes import SCOPE_ZAKEN_ALLES_LEZEN
from .factories import ZaakFactory
from .utils import ZAAK_READ_KWARGS, get_catalogus_response, get_zaaktype_response


@tag("api_roles")
@override_settings(ALLOWED_HOSTS=["testserver"])
class ZaakRoleTests(JWTAuthMixin, APITestCase):
    scopes = [SCOPE_ZAKEN_ALLES_LEZEN]
    component = ComponentTypes.zrc
    max_vertrouwelijkheidaanduiding = VertrouwelijkheidsAanduiding.confidentieel

    def setUp(self):
        super().setUp()
        token = generate_jwt_auth(
            self.client_id,
            self.secret,
            user_id=self.user_id,
            user_representation=self.user_representation,
            roles=["role1"],
        )
        self.client.credentials(HTTP_AUTHORIZATION=token)

    @classmethod
    def setUpTestData(cls):
        cls.zaaktype = ZaakTypeFactory.create()
        cls.zaaktype2 = ZaakTypeFactory.create()
        super().setUpTestData()

        Autorisatie.objects.create(
            applicatie=cls.applicatie,
            component=cls.component,
            scopes=cls.scopes,
            zaaktype=cls.check_for_instance(cls.zaaktype2),
            max_vertrouwelijkheidaanduiding=cls.max_vertrouwelijkheidaanduiding,
        )

    def test_zaak_list(self):
        """
        Assert you can only list ZAAKen of the zaaktypes and vertrouwelijkheidaanduiding
        of your role
        """
        zaaktype_url = f"http://testserver{reverse(self.zaaktype)}"
        RoleFactory.create(
            name="Role 1",
            slug="role1",
            zaaktype=zaaktype_url,
            max_vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.vertrouwelijk,
        )

        # The only zaak that should show up
        ZaakFactory.create(
            zaaktype=self.zaaktype,
            vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.vertrouwelijk,
        )

        # Should not appear
        ZaakFactory.create(
            zaaktype=self.zaaktype,
            vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.confidentieel,
        )
        ZaakFactory.create(
            zaaktype=self.zaaktype,
            vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.zeer_geheim,
        )
        ZaakFactory.create(
            zaaktype=self.zaaktype2,
            vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.openbaar,
        )
        url = reverse("zaak-list")

        response = self.client.get(url, **ZAAK_READ_KWARGS)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        results = response.data["results"]

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["zaaktype"], zaaktype_url)
        self.assertEqual(
            results[0]["vertrouwelijkheidaanduiding"],
            VertrouwelijkheidsAanduiding.vertrouwelijk,
        )

    def test_zaak_list_permissions_cannot_exceed_application_zaaktypen(self):
        """
        Assert role zaaktypen permissions cannot exceed applicatie zaaktypen permissions
        """
        zaaktype3 = ZaakTypeFactory.create()
        zaaktype_url3 = f"http://testserver{reverse(zaaktype3)}"
        RoleFactory.create(
            name="Role 1",
            slug="role1",
            zaaktype=zaaktype_url3,
            max_vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.vertrouwelijk,
        )

        # Should not appear
        ZaakFactory.create(
            zaaktype=zaaktype3,
            vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.openbaar,
        )

        url = reverse("zaak-list")

        response = self.client.get(url, **ZAAK_READ_KWARGS)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        results = response.data["results"]

        self.assertEqual(len(results), 0)

    def test_zaak_list_permissions_cannot_exceed_application_vertrouwelijkheidsaanduiding(
        self,
    ):
        """
        Assert role vertrouwelijkheidsaanduiding permissions cannot exceed applicatie
        vertrouwelijkheidsaanduiding permissions
        """
        zaaktype_url = f"http://testserver{reverse(self.zaaktype)}"
        RoleFactory.create(
            name="Role 1",
            slug="role1",
            zaaktype=zaaktype_url,
            max_vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.zeer_geheim,
        )
        # Should not appear
        ZaakFactory.create(
            zaaktype=self.zaaktype,
            vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.zeer_geheim,
        )

        url = reverse("zaak-list")

        response = self.client.get(url, **ZAAK_READ_KWARGS)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        results = response.data["results"]

        self.assertEqual(len(results), 0)

    def test_zaak_list_external(self):
        catalogus = "https://externe.catalogus.nl/api/v1/catalogussen/1c8e36be-338c-4c07-ac5e-1adf55bec04a"
        zaaktype2 = "https://externe.catalogus.nl/api/v1/zaaktypen/b71f72ef-198d-44d8-af64-ae1932df830a"

        Autorisatie.objects.create(
            applicatie=self.applicatie,
            component=self.component,
            scopes=self.scopes,
            zaaktype=zaaktype2,
            max_vertrouwelijkheidaanduiding=self.max_vertrouwelijkheidaanduiding,
        )

        RoleFactory.create(
            name="Role 1",
            slug="role1",
            zaaktype=zaaktype2,
            max_vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.vertrouwelijk,
        )

        # The only zaak that should show up
        ZaakFactory.create(
            zaaktype=zaaktype2,
            vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.vertrouwelijk,
        )

        # Should not appear
        ZaakFactory.create(
            zaaktype=zaaktype2,
            vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.confidentieel,
        )
        ZaakFactory.create(
            zaaktype=zaaktype2,
            vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.zeer_geheim,
        )
        ZaakFactory.create(
            zaaktype=self.zaaktype,
            vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.openbaar,
        )
        url = reverse("zaak-list")

        with requests_mock.Mocker(real_http=True) as m:
            m.register_uri(
                "GET", zaaktype2, json=get_zaaktype_response(catalogus, zaaktype2),
            )
            m.register_uri(
                "GET", catalogus, json=get_catalogus_response(catalogus, zaaktype2),
            )
            response = self.client.get(url, **ZAAK_READ_KWARGS)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        results = response.data["results"]

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["zaaktype"], zaaktype2)
        self.assertEqual(
            results[0]["vertrouwelijkheidaanduiding"],
            VertrouwelijkheidsAanduiding.vertrouwelijk,
        )

    def test_zaak_retrieve(self):
        """
        Assert you can only read ZAAKen of the zaaktypes and vertrouwelijkheidaanduiding
        of your authorization
        """
        zaaktype_url = f"http://testserver{reverse(self.zaaktype)}"

        RoleFactory.create(
            name="Role 1",
            slug="role1",
            zaaktype=zaaktype_url,
            max_vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.vertrouwelijk,
        )

        zaak1 = ZaakFactory.create(
            zaaktype=self.zaaktype,
            vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.vertrouwelijk,
        )

        zaak2 = ZaakFactory.create(
            zaaktype=self.zaaktype,
            vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.zeer_geheim,
        )
        zaak3 = ZaakFactory.create(
            zaaktype=self.zaaktype2,
            vertrouwelijkheidaanduiding=VertrouwelijkheidsAanduiding.openbaar,
        )
        url1 = reverse(zaak1)
        url2 = reverse(zaak2)
        url3 = reverse(zaak3)

        response1 = self.client.get(url1, **ZAAK_READ_KWARGS)
        response2 = self.client.get(url2, **ZAAK_READ_KWARGS)
        response3 = self.client.get(url3, **ZAAK_READ_KWARGS)

        self.assertEqual(response1.status_code, status.HTTP_200_OK)
        self.assertEqual(response2.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response2.status_code, status.HTTP_403_FORBIDDEN)
