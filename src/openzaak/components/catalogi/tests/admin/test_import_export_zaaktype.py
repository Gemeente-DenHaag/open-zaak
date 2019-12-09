import io
import zipfile
from unittest.mock import patch

from django.test import override_settings
from django.urls import reverse
from django.utils.translation import ugettext as _

import requests_mock
from django_webtest import TransactionWebTest, WebTest
from zds_client.tests.mocks import mock_client

from openzaak.accounts.tests.factories import SuperUserFactory

from ...models import (
    BesluitType,
    Catalogus,
    Eigenschap,
    InformatieObjectType,
    ResultaatType,
    RolType,
    StatusType,
    ZaakType,
    ZaakTypeInformatieObjectType,
)
from ..factories import (
    BesluitTypeFactory,
    CatalogusFactory,
    EigenschapFactory,
    InformatieObjectTypeFactory,
    ResultaatTypeFactory,
    RolTypeFactory,
    StatusTypeFactory,
    ZaakTypeFactory,
    ZaakTypeInformatieObjectTypeFactory,
)


class ZaakTypeAdminImportExportTests(WebTest):
    @classmethod
    def setUpTestData(cls):
        cls.user = SuperUserFactory.create()

    def setUp(self):
        super().setUp()

        self.app.set_user(self.user)

    @override_settings(LINK_FETCHER="vng_api_common.mocks.link_fetcher_200")
    @patch("vng_api_common.validators.fetcher")
    @patch("vng_api_common.validators.obj_has_shape", return_value=True)
    def test_export_import_zaaktype_with_relations(self, *mocks):
        catalogus = CatalogusFactory.create(rsin="000000000", domein="TEST")
        zaaktype = ZaakTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            zaaktype_omschrijving="bla",
        )
        informatieobjecttype = InformatieObjectTypeFactory.create(
            catalogus=catalogus, vertrouwelijkheidaanduiding="openbaar"
        )
        besluittype = BesluitTypeFactory.create(catalogus=catalogus)
        besluittype.zaaktypen.all().delete()
        besluittype.zaaktypen.set([zaaktype])
        besluittype.informatieobjecttypen.set([informatieobjecttype])
        ziot = ZaakTypeInformatieObjectTypeFactory.create(
            zaaktype=zaaktype, informatieobjecttype=informatieobjecttype
        )
        statustype = StatusTypeFactory.create(
            zaaktype=zaaktype, statustype_omschrijving="bla"
        )
        roltype = RolTypeFactory.create(zaaktype=zaaktype)
        resultaattype = ResultaatTypeFactory.create(
            zaaktype=zaaktype,
            omschrijving_generiek="bla",
            brondatum_archiefprocedure_afleidingswijze="ander_datumkenmerk",
            brondatum_archiefprocedure_datumkenmerk="datum",
            brondatum_archiefprocedure_registratie="bla",
            brondatum_archiefprocedure_objecttype="besluit",
        )

        eigenschap = EigenschapFactory.create(zaaktype=zaaktype, definitie="bla")
        Catalogus.objects.exclude(pk=catalogus.pk).delete()

        url = reverse("admin:catalogi_zaaktype_change", args=(zaaktype.pk,))

        response = self.app.get(url)
        form = response.forms["zaaktype_form"]

        response = form.submit("_export")

        data = response.content

        zaaktype.refresh_from_db()
        zaaktype.delete()
        informatieobjecttype.delete()
        besluittype.delete()
        url = reverse("admin:catalogi_catalogus_import_zaaktype", args=(catalogus.pk,))

        response = self.app.get(url)

        form = response.form
        f = io.BytesIO(data)
        f.name = "test.zip"
        f.seek(0)
        form["file"] = (
            "test.zip",
            f.read(),
        )

        responses = {
            resultaattype.resultaattypeomschrijving: {
                "url": resultaattype.resultaattypeomschrijving,
                "omschrijving": "bla",
                "definitie": "bla",
                "opmerking": "adasdasd",
            },
            resultaattype.selectielijstklasse: {
                "url": resultaattype.selectielijstklasse,
                "procesType": zaaktype.selectielijst_procestype,
                "nummer": 1,
                "naam": "bla",
                "herkomst": "adsad",
                "waardering": "blijvend_bewaren",
                "procestermijn": "P5Y",
            },
        }

        with requests_mock.Mocker() as m:
            m.get(resultaattype.resultaattypeomschrijving, json={"omschrijving": "bla"})
            with mock_client(responses):
                response = form.submit("_import_zaaktype")
                response = response.form.submit("_select")

        imported_catalogus = Catalogus.objects.get()
        besluittype = BesluitType.objects.get()
        informatieobjecttype = InformatieObjectType.objects.get()
        zaaktype = ZaakType.objects.get()
        ziot = ZaakTypeInformatieObjectType.objects.get()
        roltype = RolType.objects.get()
        resultaattype = ResultaatType.objects.get()
        statustype = StatusType.objects.get()
        eigenschap = Eigenschap.objects.get()

        self.assertEqual(besluittype.catalogus, imported_catalogus)
        self.assertTrue(besluittype.concept)
        self.assertEqual(list(besluittype.zaaktypen.all()), [zaaktype])
        self.assertEqual(
            list(besluittype.informatieobjecttypen.all()), [informatieobjecttype]
        )

        self.assertEqual(informatieobjecttype.catalogus, imported_catalogus)
        self.assertTrue(informatieobjecttype.concept)

        self.assertEqual(zaaktype.catalogus, imported_catalogus)
        self.assertTrue(zaaktype.concept)

        self.assertEqual(ziot.zaaktype, zaaktype)
        self.assertEqual(ziot.informatieobjecttype, informatieobjecttype)

        self.assertEqual(roltype.zaaktype, zaaktype)
        self.assertEqual(resultaattype.zaaktype, zaaktype)
        self.assertEqual(statustype.zaaktype, zaaktype)
        self.assertEqual(eigenschap.zaaktype, zaaktype)

    @override_settings(LINK_FETCHER="vng_api_common.mocks.link_fetcher_200")
    @patch("vng_api_common.validators.fetcher")
    @patch("vng_api_common.validators.obj_has_shape", return_value=True)
    def test_export_import_zaaktype_to_different_catalogus(self, *mocks):
        catalogus = CatalogusFactory.create(rsin="000000000", domein="TEST")
        zaaktype = ZaakTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            zaaktype_omschrijving="bla",
        )
        informatieobjecttype = InformatieObjectTypeFactory.create(
            catalogus=catalogus, vertrouwelijkheidaanduiding="openbaar"
        )
        besluittype = BesluitTypeFactory.create(catalogus=catalogus)
        besluittype.zaaktypen.all().delete()
        besluittype.zaaktypen.set([zaaktype])
        besluittype.informatieobjecttypen.set([informatieobjecttype])
        ziot = ZaakTypeInformatieObjectTypeFactory.create(
            zaaktype=zaaktype, informatieobjecttype=informatieobjecttype
        )
        statustype = StatusTypeFactory.create(
            zaaktype=zaaktype, statustype_omschrijving="bla"
        )
        roltype = RolTypeFactory.create(zaaktype=zaaktype)
        resultaattype = ResultaatTypeFactory.create(
            zaaktype=zaaktype,
            omschrijving_generiek="bla",
            brondatum_archiefprocedure_afleidingswijze="ander_datumkenmerk",
            brondatum_archiefprocedure_datumkenmerk="datum",
            brondatum_archiefprocedure_registratie="bla",
            brondatum_archiefprocedure_objecttype="besluit",
        )

        eigenschap = EigenschapFactory.create(zaaktype=zaaktype, definitie="bla")
        Catalogus.objects.exclude(pk=catalogus.pk).delete()

        url = reverse("admin:catalogi_zaaktype_change", args=(zaaktype.pk,))

        response = self.app.get(url)
        form = response.forms["zaaktype_form"]

        response = form.submit("_export")

        data = response.content

        zaaktype.refresh_from_db()
        catalogus.delete()

        catalogus = CatalogusFactory.create(rsin="015006864", domein="TEST2")
        url = reverse("admin:catalogi_catalogus_import_zaaktype", args=(catalogus.pk,))

        response = self.app.get(url)

        form = response.form
        f = io.BytesIO(data)
        f.name = "test.zip"
        f.seek(0)
        form["file"] = (
            "test.zip",
            f.read(),
        )

        responses = {
            resultaattype.resultaattypeomschrijving: {
                "url": resultaattype.resultaattypeomschrijving,
                "omschrijving": "bla",
                "definitie": "bla",
                "opmerking": "adasdasd",
            },
            resultaattype.selectielijstklasse: {
                "url": resultaattype.selectielijstklasse,
                "procesType": zaaktype.selectielijst_procestype,
                "nummer": 1,
                "naam": "bla",
                "herkomst": "adsad",
                "waardering": "blijvend_bewaren",
                "procestermijn": "P5Y",
            },
        }

        with requests_mock.Mocker() as m:
            m.get(resultaattype.resultaattypeomschrijving, json={"omschrijving": "bla"})
            with mock_client(responses):
                response = form.submit("_import_zaaktype")
                response = response.form.submit("_select")

        imported_catalogus = Catalogus.objects.get()
        besluittype = BesluitType.objects.get()
        informatieobjecttype = InformatieObjectType.objects.get()
        zaaktype = ZaakType.objects.get()
        ziot = ZaakTypeInformatieObjectType.objects.get()
        roltype = RolType.objects.get()
        resultaattype = ResultaatType.objects.get()
        statustype = StatusType.objects.get()
        eigenschap = Eigenschap.objects.get()

        self.assertEqual(besluittype.catalogus, imported_catalogus)
        self.assertTrue(besluittype.concept)
        self.assertEqual(list(besluittype.zaaktypen.all()), [zaaktype])
        self.assertEqual(
            list(besluittype.informatieobjecttypen.all()), [informatieobjecttype]
        )

        self.assertEqual(informatieobjecttype.catalogus, imported_catalogus)
        self.assertTrue(informatieobjecttype.concept)

        self.assertEqual(zaaktype.catalogus, imported_catalogus)
        self.assertTrue(zaaktype.concept)

        self.assertEqual(ziot.zaaktype, zaaktype)
        self.assertEqual(ziot.informatieobjecttype, informatieobjecttype)

        self.assertEqual(roltype.zaaktype, zaaktype)
        self.assertEqual(resultaattype.zaaktype, zaaktype)
        self.assertEqual(statustype.zaaktype, zaaktype)
        self.assertEqual(eigenschap.zaaktype, zaaktype)

    def test_export_import_zaaktype_choose_existing_informatieobjecttype(self):
        catalogus = CatalogusFactory.create(rsin="000000000", domein="TEST")
        zaaktype = ZaakTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            zaaktype_omschrijving="bla",
        )
        informatieobjecttype = InformatieObjectTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            omschrijving="export",
        )
        besluittype = BesluitTypeFactory.create(catalogus=catalogus)
        besluittype.zaaktypen.all().delete()
        besluittype.zaaktypen.set([zaaktype])
        besluittype.informatieobjecttypen.set([informatieobjecttype])
        ziot = ZaakTypeInformatieObjectTypeFactory.create(
            zaaktype=zaaktype, informatieobjecttype=informatieobjecttype
        )

        url = reverse("admin:catalogi_zaaktype_change", args=(zaaktype.pk,))

        response = self.app.get(url)
        form = response.forms["zaaktype_form"]

        response = form.submit("_export")

        data = response.content

        zaaktype.refresh_from_db()
        zaaktype.delete()
        informatieobjecttype.delete()
        besluittype.delete()

        informatieobjecttype = InformatieObjectTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            omschrijving="existing",
        )
        informatieobjecttype_uuid = informatieobjecttype.uuid
        Catalogus.objects.exclude(pk=catalogus.pk).delete()

        url = reverse("admin:catalogi_catalogus_import_zaaktype", args=(catalogus.pk,))

        response = self.app.get(url)

        form = response.form
        f = io.BytesIO(data)
        f.name = "test.zip"
        f.seek(0)
        form["file"] = (
            "test.zip",
            f.read(),
        )

        response = form.submit("_import_zaaktype")

        response.form["iotype-0-existing"] = informatieobjecttype.id
        response = response.form.submit("_select")

        imported_catalogus = Catalogus.objects.get()
        besluittype = BesluitType.objects.get()
        informatieobjecttype = InformatieObjectType.objects.get()
        zaaktype = ZaakType.objects.get()
        ziot = ZaakTypeInformatieObjectType.objects.get()

        self.assertEqual(besluittype.catalogus, imported_catalogus)
        self.assertEqual(list(besluittype.zaaktypen.all()), [zaaktype])
        self.assertEqual(
            list(besluittype.informatieobjecttypen.all()), [informatieobjecttype]
        )

        self.assertEqual(informatieobjecttype.catalogus, imported_catalogus)
        self.assertEqual(informatieobjecttype.omschrijving, "existing")
        self.assertEqual(informatieobjecttype.uuid, informatieobjecttype_uuid)

        self.assertEqual(zaaktype.catalogus, imported_catalogus)

        self.assertEqual(ziot.zaaktype, zaaktype)
        self.assertEqual(ziot.informatieobjecttype, informatieobjecttype)

    def test_export_import_zaaktype_choose_existing_besluittype(self):
        catalogus = CatalogusFactory.create(rsin="000000000", domein="TEST")
        zaaktype = ZaakTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            zaaktype_omschrijving="bla",
        )
        informatieobjecttype = InformatieObjectTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            omschrijving="export",
        )
        besluittype = BesluitTypeFactory.create(
            catalogus=catalogus, omschrijving="export"
        )
        besluittype.zaaktypen.all().delete()
        besluittype.zaaktypen.set([zaaktype])
        besluittype.informatieobjecttypen.set([informatieobjecttype])
        ziot = ZaakTypeInformatieObjectTypeFactory.create(
            zaaktype=zaaktype, informatieobjecttype=informatieobjecttype
        )

        url = reverse("admin:catalogi_zaaktype_change", args=(zaaktype.pk,))

        response = self.app.get(url)
        form = response.forms["zaaktype_form"]

        response = form.submit("_export")

        data = response.content

        zaaktype.refresh_from_db()
        zaaktype.delete()
        informatieobjecttype.delete()
        besluittype.delete()

        besluittype = BesluitTypeFactory.create(
            catalogus=catalogus, omschrijving="existing"
        )
        besluittype_uuid = besluittype.uuid
        besluittype.zaaktypen.all().delete()
        Catalogus.objects.exclude(pk=catalogus.pk).delete()

        url = reverse("admin:catalogi_catalogus_import_zaaktype", args=(catalogus.pk,))

        response = self.app.get(url)

        form = response.form
        f = io.BytesIO(data)
        f.name = "test.zip"
        f.seek(0)
        form["file"] = (
            "test.zip",
            f.read(),
        )

        response = form.submit("_import_zaaktype")

        response.form["besluittype-0-existing"] = besluittype.id
        response = response.form.submit("_select")

        imported_catalogus = Catalogus.objects.get()
        besluittype = BesluitType.objects.get()
        informatieobjecttype = InformatieObjectType.objects.get()
        zaaktype = ZaakType.objects.get()
        ziot = ZaakTypeInformatieObjectType.objects.get()

        self.assertEqual(besluittype.catalogus, imported_catalogus)
        self.assertEqual(besluittype.omschrijving, "existing")
        self.assertEqual(besluittype.uuid, besluittype_uuid)
        self.assertEqual(list(besluittype.zaaktypen.all()), [zaaktype])
        self.assertEqual(
            list(besluittype.informatieobjecttypen.all()), [informatieobjecttype]
        )

        self.assertEqual(informatieobjecttype.catalogus, imported_catalogus)

        self.assertEqual(zaaktype.catalogus, imported_catalogus)

        self.assertEqual(ziot.zaaktype, zaaktype)
        self.assertEqual(ziot.informatieobjecttype, informatieobjecttype)

    def test_export_import_zaaktype_choose_existing_besluittype_and_informatieobjecttype(
        self,
    ):
        catalogus = CatalogusFactory.create(rsin="000000000", domein="TEST")
        zaaktype = ZaakTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            zaaktype_omschrijving="bla",
        )
        informatieobjecttype = InformatieObjectTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            omschrijving="export",
        )
        besluittype = BesluitTypeFactory.create(
            catalogus=catalogus, omschrijving="export"
        )
        besluittype.zaaktypen.all().delete()
        besluittype.zaaktypen.set([zaaktype])
        besluittype.informatieobjecttypen.set([informatieobjecttype])
        ziot = ZaakTypeInformatieObjectTypeFactory.create(
            zaaktype=zaaktype, informatieobjecttype=informatieobjecttype
        )

        url = reverse("admin:catalogi_zaaktype_change", args=(zaaktype.pk,))

        response = self.app.get(url)
        form = response.forms["zaaktype_form"]

        response = form.submit("_export")

        data = response.content

        zaaktype.refresh_from_db()
        zaaktype.delete()
        informatieobjecttype.delete()
        besluittype.delete()

        informatieobjecttype = InformatieObjectTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            omschrijving="existing",
        )
        besluittype = BesluitTypeFactory.create(
            catalogus=catalogus, omschrijving="existing"
        )
        besluittype.zaaktypen.all().delete()
        Catalogus.objects.exclude(pk=catalogus.pk).delete()

        url = reverse("admin:catalogi_catalogus_import_zaaktype", args=(catalogus.pk,))

        response = self.app.get(url)

        form = response.form
        f = io.BytesIO(data)
        f.name = "test.zip"
        f.seek(0)
        form["file"] = (
            "test.zip",
            f.read(),
        )

        response = form.submit("_import_zaaktype")

        response.form["besluittype-0-existing"] = besluittype.id
        response.form["iotype-0-existing"] = informatieobjecttype.id
        response = response.form.submit("_select")

        imported_catalogus = Catalogus.objects.get()
        besluittype = BesluitType.objects.get()
        informatieobjecttype = InformatieObjectType.objects.get()
        zaaktype = ZaakType.objects.get()
        ziot = ZaakTypeInformatieObjectType.objects.get()

        self.assertEqual(besluittype.catalogus, imported_catalogus)
        self.assertEqual(besluittype.omschrijving, "existing")
        self.assertEqual(list(besluittype.zaaktypen.all()), [zaaktype])
        self.assertEqual(
            list(besluittype.informatieobjecttypen.all()), [informatieobjecttype]
        )

        self.assertEqual(informatieobjecttype.catalogus, imported_catalogus)
        self.assertEqual(informatieobjecttype.omschrijving, "existing")

        self.assertEqual(zaaktype.catalogus, imported_catalogus)

        self.assertEqual(ziot.zaaktype, zaaktype)
        self.assertEqual(ziot.informatieobjecttype, informatieobjecttype)

    def test_import_zaaktype_create_new_generates_new_uuids(self):
        catalogus = CatalogusFactory.create(rsin="000000000", domein="TEST")
        zaaktype = ZaakTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            zaaktype_omschrijving="bla",
        )
        zaaktype_uuid = zaaktype.uuid
        informatieobjecttype = InformatieObjectTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            omschrijving="export",
        )
        informatieobjecttype_uuid = informatieobjecttype.uuid
        ziot = ZaakTypeInformatieObjectTypeFactory.create(
            zaaktype=zaaktype, informatieobjecttype=informatieobjecttype
        )
        besluittype = BesluitTypeFactory.create(catalogus=catalogus)
        besluittype_uuid = besluittype.uuid
        besluittype.zaaktypen.all().delete()
        besluittype.zaaktypen.set([zaaktype])
        Catalogus.objects.exclude(pk=catalogus.pk).delete()
        ZaakType.objects.exclude(pk=zaaktype.pk).delete()

        url = reverse("admin:catalogi_zaaktype_change", args=(zaaktype.pk,))

        response = self.app.get(url)
        form = response.forms["zaaktype_form"]

        response = form.submit("_export")

        data = response.content

        zaaktype.delete()
        informatieobjecttype.delete()
        besluittype.delete()

        url = reverse("admin:catalogi_catalogus_import_zaaktype", args=(catalogus.pk,))

        response = self.app.get(url)

        form = response.form
        f = io.BytesIO(data)
        f.name = "test.zip"
        f.seek(0)
        form["file"] = (
            "test.zip",
            f.read(),
        )

        response = form.submit("_import_zaaktype")
        response = response.form.submit("_select")

        zaaktype = ZaakType.objects.get()
        informatieobjecttype = InformatieObjectType.objects.get()
        besluittype = BesluitType.objects.get()

        self.assertNotEqual(zaaktype.uuid, zaaktype_uuid)
        self.assertNotEqual(informatieobjecttype.uuid, informatieobjecttype_uuid)
        self.assertNotEqual(besluittype.uuid, besluittype_uuid)

    def test_simultaneous_zaaktype_imports(self):
        catalogus = CatalogusFactory.create(rsin="000000000", domein="TEST")
        zaaktype1 = ZaakTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="geheim",
            zaaktype_omschrijving="zaaktype1",
        )
        zaaktype2 = ZaakTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            zaaktype_omschrijving="zaaktype2",
        )
        besluittype1 = BesluitTypeFactory.create(catalogus=catalogus, omschrijving="1")
        besluittype1.zaaktypen.set([zaaktype1])

        besluittype2 = BesluitTypeFactory.create(catalogus=catalogus, omschrijving="2")
        besluittype2.zaaktypen.set([zaaktype2])

        url = reverse("admin:catalogi_zaaktype_change", args=(zaaktype1.pk,))
        response = self.app.get(url)
        form = response.forms["zaaktype_form"]
        response = form.submit("_export")
        data_zaaktype1 = response.content

        url = reverse("admin:catalogi_zaaktype_change", args=(zaaktype2.pk,))
        response = self.app.get(url)
        form = response.forms["zaaktype_form"]
        response = form.submit("_export")
        data_zaaktype2 = response.content

        ZaakType.objects.all().delete()
        BesluitType.objects.all().delete()

        url = reverse("admin:catalogi_catalogus_import_zaaktype", args=(catalogus.pk,))

        self.app2 = self.app_class()

        user2 = SuperUserFactory.create()
        self.app2.set_user(user2)

        response = self.app.get(url)

        form = response.form
        f = io.BytesIO(data_zaaktype1)
        f.name = "test.zip"
        f.seek(0)
        form["file"] = (
            "test.zip",
            f.read(),
        )

        response = form.submit("_import_zaaktype")

        response2 = self.app2.get(url)

        form = response2.form
        f = io.BytesIO(data_zaaktype2)
        f.name = "test2.zip"
        f.seek(0)
        form["file"] = (
            "test2.zip",
            f.read(),
        )

        response2 = form.submit("_import_zaaktype")

        response = response.form.submit("_select")

        imported_catalogus = Catalogus.objects.get()
        zaaktype = ZaakType.objects.get()

        self.assertEqual(zaaktype.zaaktype_omschrijving, "zaaktype1")

        response2 = response2.form.submit("_select")

        self.assertEqual(ZaakType.objects.count(), 2)
        zaaktype1, zaaktype2 = ZaakType.objects.all()

        self.assertEqual(zaaktype1.zaaktype_omschrijving, "zaaktype1")
        self.assertEqual(zaaktype2.zaaktype_omschrijving, "zaaktype2")

        self.assertEqual(BesluitType.objects.count(), 2)
        besluittype1, besluittype2 = BesluitType.objects.all()

        self.assertEqual(besluittype1.omschrijving, "1")
        self.assertEqual(besluittype2.omschrijving, "2")

    def test_import_button_not_visible_on_create_new_catalogus(self):
        url = reverse("admin:catalogi_catalogus_add")

        response = self.app.get(url)

        import_button = response.html.find("input", {"name": "_import_zaaktype"})
        self.assertIsNone(import_button)


class ZaakTypeAdminImportExportTransactionTests(TransactionWebTest):
    def setUp(self):
        super().setUp()

        self.app.set_user(SuperUserFactory.create())

    def test_import_zaaktype_already_exists(self):
        catalogus = CatalogusFactory.create(rsin="000000000", domein="TEST")
        zaaktype = ZaakTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            zaaktype_omschrijving="bla",
        )

        url = reverse("admin:catalogi_zaaktype_change", args=(zaaktype.pk,))

        response = self.app.get(url)
        form = response.forms["zaaktype_form"]

        response = form.submit("_export")

        data = response.content

        url = reverse("admin:catalogi_catalogus_import_zaaktype", args=(catalogus.pk,))

        response = self.app.get(url)

        form = response.form
        f = io.BytesIO(data)
        f.name = "test.zip"
        f.seek(0)
        form["file"] = (
            "test.zip",
            f.read(),
        )

        response = form.submit("_import_zaaktype")

        self.assertIn(
            _("A validation error occurred while deserializing a ZaakType"),
            response.text,
        )
        self.assertEqual(ZaakType.objects.count(), 1)

    def test_import_zaaktype_already_exists_with_besluittype(self):
        catalogus = CatalogusFactory.create(rsin="000000000", domein="TEST")
        zaaktype = ZaakTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            zaaktype_omschrijving="bla",
        )
        besluittype = BesluitTypeFactory.create(catalogus=catalogus)
        besluittype.zaaktypen.all().delete()
        besluittype.zaaktypen.set([zaaktype])
        Catalogus.objects.exclude(pk=catalogus.pk).delete()

        url = reverse("admin:catalogi_zaaktype_change", args=(zaaktype.pk,))

        response = self.app.get(url)
        form = response.forms["zaaktype_form"]

        response = form.submit("_export")

        data = response.content

        besluittype.delete()

        url = reverse("admin:catalogi_catalogus_import_zaaktype", args=(catalogus.pk,))

        response = self.app.get(url)

        form = response.form
        f = io.BytesIO(data)
        f.name = "test.zip"
        f.seek(0)
        form["file"] = (
            "test.zip",
            f.read(),
        )

        response = form.submit("_import_zaaktype")
        response = response.form.submit("_select")

        self.assertIn(
            _("A validation error occurred while deserializing a ZaakType"),
            response.text,
        )
        self.assertEqual(ZaakType.objects.count(), 1)
        self.assertEqual(BesluitType.objects.count(), 0)

    def test_import_zaaktype_besluittype_already_exists(self):
        catalogus = CatalogusFactory.create(rsin="000000000", domein="TEST")
        zaaktype = ZaakTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            zaaktype_omschrijving="bla",
        )
        besluittype = BesluitTypeFactory.create(catalogus=catalogus)
        besluittype.zaaktypen.all().delete()
        besluittype.zaaktypen.set([zaaktype])
        Catalogus.objects.exclude(pk=catalogus.pk).delete()

        url = reverse("admin:catalogi_zaaktype_change", args=(zaaktype.pk,))

        response = self.app.get(url)
        form = response.forms["zaaktype_form"]

        response = form.submit("_export")

        data = response.content

        zaaktype.delete()

        url = reverse("admin:catalogi_catalogus_import_zaaktype", args=(catalogus.pk,))

        response = self.app.get(url)

        form = response.form
        f = io.BytesIO(data)
        f.name = "test.zip"
        f.seek(0)
        form["file"] = (
            "test.zip",
            f.read(),
        )

        response = form.submit("_import_zaaktype")
        response = response.form.submit("_select")

        self.assertIn(
            _("A validation error occurred while deserializing a BesluitType"),
            response.text,
        )
        self.assertEqual(BesluitType.objects.count(), 1)
        self.assertEqual(ZaakType.objects.count(), 0)

    def test_import_zaaktype_informatieobjectype_already_exists(self):
        catalogus = CatalogusFactory.create(rsin="000000000", domein="TEST")
        zaaktype = ZaakTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            zaaktype_omschrijving="bla",
        )
        informatieobjecttype = InformatieObjectTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            omschrijving="export",
        )
        ziot = ZaakTypeInformatieObjectTypeFactory.create(
            zaaktype=zaaktype, informatieobjecttype=informatieobjecttype
        )
        ZaakType.objects.exclude(pk=zaaktype.pk).delete()

        url = reverse("admin:catalogi_zaaktype_change", args=(zaaktype.pk,))

        response = self.app.get(url)
        form = response.forms["zaaktype_form"]

        response = form.submit("_export")

        data = response.content

        zaaktype.delete()

        url = reverse("admin:catalogi_catalogus_import_zaaktype", args=(catalogus.pk,))

        response = self.app.get(url)

        form = response.form
        f = io.BytesIO(data)
        f.name = "test.zip"
        f.seek(0)
        form["file"] = (
            "test.zip",
            f.read(),
        )

        response = form.submit("_import_zaaktype")
        response = response.form.submit("_select")

        self.assertIn(
            _("A validation error occurred while deserializing a InformatieObjectType"),
            response.text,
        )
        self.assertEqual(InformatieObjectType.objects.count(), 1)
        self.assertEqual(ZaakType.objects.count(), 0)

    def test_import_zaaktype_besluittype_invalid_eigenschap(self):
        catalogus = CatalogusFactory.create(rsin="000000000", domein="TEST")
        zaaktype = ZaakTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            zaaktype_omschrijving="bla",
        )
        besluittype = BesluitTypeFactory.create(catalogus=catalogus)
        besluittype.zaaktypen.all().delete()
        besluittype.zaaktypen.set([zaaktype])
        Catalogus.objects.exclude(pk=catalogus.pk).delete()

        url = reverse("admin:catalogi_zaaktype_change", args=(zaaktype.pk,))

        response = self.app.get(url)
        form = response.forms["zaaktype_form"]

        response = form.submit("_export")

        data = response.content

        zaaktype.delete()
        besluittype.delete()

        url = reverse("admin:catalogi_catalogus_import_zaaktype", args=(catalogus.pk,))

        response = self.app.get(url)

        form = response.form
        f = io.BytesIO(data)
        f.name = "test.zip"
        f.seek(0)

        with zipfile.ZipFile(f, "a") as zip_file:
            zip_file.writestr("Eigenschap.json", '[{"incorrect": "data"}]')

        f.seek(0)

        form["file"] = (
            "test.zip",
            f.read(),
        )

        response = form.submit("_import_zaaktype")
        response = response.form.submit("_select")

        self.assertIn(
            _("A validation error occurred while deserializing a Eigenschap"),
            response.text,
        )
        self.assertEqual(BesluitType.objects.count(), 0)
        self.assertEqual(ZaakType.objects.count(), 0)
        self.assertEqual(Eigenschap.objects.count(), 0)

    def test_import_zaaktype_invalid_eigenschap(self):
        catalogus = CatalogusFactory.create(rsin="000000000", domein="TEST")
        zaaktype = ZaakTypeFactory.create(
            catalogus=catalogus,
            vertrouwelijkheidaanduiding="openbaar",
            zaaktype_omschrijving="bla",
        )
        Catalogus.objects.exclude(pk=catalogus.pk).delete()

        url = reverse("admin:catalogi_zaaktype_change", args=(zaaktype.pk,))

        response = self.app.get(url)
        form = response.forms["zaaktype_form"]

        response = form.submit("_export")

        data = response.content

        zaaktype.delete()

        url = reverse("admin:catalogi_catalogus_import_zaaktype", args=(catalogus.pk,))

        response = self.app.get(url)

        form = response.form
        f = io.BytesIO(data)
        f.name = "test.zip"
        f.seek(0)

        with zipfile.ZipFile(f, "a") as zip_file:
            zip_file.writestr("Eigenschap.json", '[{"incorrect": "data"}]')

        f.seek(0)

        form["file"] = (
            "test.zip",
            f.read(),
        )

        response = form.submit("_import_zaaktype")

        self.assertIn(
            _("A validation error occurred while deserializing a Eigenschap"),
            response.text,
        )
        self.assertEqual(ZaakType.objects.count(), 0)
        self.assertEqual(Eigenschap.objects.count(), 0)
