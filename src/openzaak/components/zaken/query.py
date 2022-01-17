# SPDX-License-Identifier: EUPL-1.2
# Copyright (C) 2019 - 2022 Dimpact
from typing import Dict, Tuple
from urllib.parse import urlparse

from django.conf import settings
from django.db import models
from django.http.request import validate_host

from django_loose_fk.virtual_models import ProxyMixin
from vng_api_common.scopes import Scope

from openzaak.components.besluiten.models import Besluit
from openzaak.utils.query import BlockChangeMixin, LooseFkAuthorizationsFilterMixin


class ZaakAuthorizationsFilterMixin(LooseFkAuthorizationsFilterMixin):
    """
    Filter objects whitelisted by the authorizations.

    For ZRC, authorizations are defined around ``Autorisatie.zaaktype``,
    with a ``max_vertrouwelijkheidaanduiding`` limiting the confidentiality
    level of ``zaken`` (inclusive), and scopes that apply for the
    ``zaaktype`` at hand.

    This means that ``zaken`` are included if, and only if:

    * the ``zaaktype`` is provided in ``authorizations``
    * the scopes for the ``zaaktype`` in each ``authorization`` contain the
      required``scope``
    * the ``zaak.vertrouwelijkheidaanduiding`` is less then or equal to the
      ``authorization.max_vertrouwelijkheidaanduiding``

    :param scope: a (possibly complex) scope that must be granted on the
      authorizations
    :param authorizations: queryset of
      :class:`vng_api_common.authorizations.Autorisatie` objects

    :return: a queryset of filtered results according to the
      authorizations provided
    """

    vertrouwelijkheidaanduiding_use = True
    loose_fk_field = "zaaktype"

    def filter_for_roles(self, scope: Scope, roles: models.QuerySet) -> models.QuerySet:
        roles_local = []
        roles_external = []
        allowed_hosts = settings.ALLOWED_HOSTS
        for role in roles:
            # TODO no scope checking yet
            # test if this authorization has the scope that's needed
            # if not scope.is_contained_in(role.scopes):
            #     continue

            loose_fk_host = urlparse(getattr(role, self.loose_fk_field)).hostname
            if validate_host(loose_fk_host, allowed_hosts):
                roles_local.append(role)
            else:
                roles_external.append(role)

        ids_local = self.ids_by_auth(scope, roles_local, local=True)
        ids_external = self.ids_by_auth(scope, roles_external, local=False)
        queryset = self.filter(pk__in=ids_local.union(ids_external))

        return queryset


class ZaakQuerySet(ZaakAuthorizationsFilterMixin, models.QuerySet):
    pass


class ZaakRelatedQuerySet(ZaakAuthorizationsFilterMixin, models.QuerySet):
    authorizations_lookup = "zaak"


class ZaakInformatieObjectQuerySet(BlockChangeMixin, ZaakRelatedQuerySet):
    def filter(self, *args, **kwargs):
        if settings.CMIS_ENABLED and "informatieobject" in kwargs:
            from openzaak.components.documenten.models import (
                EnkelvoudigInformatieObject,
            )

            # If we leave the Document object, the filter will happen on pk, which is None
            # in the CMIS case. This gives an error.
            if isinstance(kwargs["informatieobject"], EnkelvoudigInformatieObject):
                kwargs["informatieobject"] = kwargs["informatieobject"].get_url()

        return super().filter(*args, **kwargs)


class ZaakBesluitQuerySet(BlockChangeMixin, ZaakRelatedQuerySet):
    def create_from(self, besluit: Besluit) -> [models.Model, None]:
        if isinstance(besluit.zaak, ProxyMixin):
            return None

        return self.create(zaak=besluit.zaak, besluit=besluit)

    def delete_for(
        self, besluit: Besluit, previous: bool = False
    ) -> Tuple[int, Dict[str, int]]:
        if isinstance(besluit.zaak, ProxyMixin):
            return (0, {})

        # fetch the instance
        if previous:
            obj = self.get(zaak=besluit.previous_zaak, besluit=besluit)
        else:
            obj = self.get(zaak=besluit.zaak, besluit=besluit)
        return obj.delete()
