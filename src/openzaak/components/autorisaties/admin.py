from django.contrib import admin
from django.forms import BaseModelFormSet
from django.urls import path, reverse
from django.utils.html import format_html
from django.utils.translation import ugettext_lazy as _

from vng_api_common.authorizations.models import (
    Applicatie,
    AuthorizationsConfig,
    Autorisatie,
)
from vng_api_common.constants import ComponentTypes
from vng_api_common.models import JWTSecret

from .admin_views import AutorisatiesView
from .forms import ApplicatieForm, CredentialsFormSet
from .utils import get_related_object

admin.site.unregister(AuthorizationsConfig)
admin.site.unregister(Applicatie)


class AutorisatieInline(admin.TabularInline):
    model = Autorisatie
    extra = 0
    fields = ["component", "scopes", "_get_extra"]
    readonly_fields = fields

    def has_add_permission(self, request, obj=None) -> bool:
        return False

    def _get_extra(self, obj) -> str:
        """
        Show the context-dependent extra fields.

        An :class:`Autorisatie` requires extra attributes depending on the
        component that it's relevant for.

        .. note:: using get_resource_for_path spawns too many queries, since
            the viewsets have prefetch_related calls.
        """
        if obj.component == ComponentTypes.zrc:
            template = (
                "<strong>Zaaktype</strong>: "
                '<a href="{admin_url}" target="_blank" rel="noopener">{zt_repr}</a>'
                "<br>"
                "<strong>Maximale vertrouwelijkheidaanduiding</strong>: "
                "{va}"
            )
            zaaktype = get_related_object(obj)
            return format_html(
                template,
                admin_url=reverse(
                    "admin:catalogi_zaaktype_change", kwargs={"object_id": zaaktype.pk}
                ),
                zt_repr=str(zaaktype),
                va=obj.get_max_vertrouwelijkheidaanduiding_display(),
            )

        if obj.component == ComponentTypes.drc:
            template = (
                "<strong>Informatieobjecttype</strong>: "
                '<a href="{admin_url}" target="_blank" rel="noopener">{iot_repr}</a>'
                "<br>"
                "<strong>Maximale vertrouwelijkheidaanduiding</strong>: "
                "{va}"
            )
            informatieobjecttype = get_related_object(obj)
            return format_html(
                template,
                admin_url=reverse(
                    "admin:catalogi_informatieobjecttype_change",
                    kwargs={"object_id": informatieobjecttype.pk},
                ),
                iot_repr=str(informatieobjecttype),
                va=obj.get_max_vertrouwelijkheidaanduiding_display(),
            )

        if obj.component == ComponentTypes.brc:
            template = (
                "<strong>Besluittype</strong>: "
                '<a href="{admin_url}" target="_blank" rel="noopener">{bt_repr}</a>'
            )
            besluittype = get_related_object(obj)
            return format_html(
                template,
                admin_url=reverse(
                    "admin:catalogi_besluittype_change",
                    kwargs={"object_id": besluittype.pk},
                ),
                bt_repr=str(besluittype),
            )

        return "foo"

    _get_extra.short_description = _("Extra parameters")


class CredentialsInline(admin.TabularInline):
    model = JWTSecret
    formset = BaseModelFormSet
    fields = ("identifier", "secret")
    extra = 1

    # Disable system checks, since this model is not related at all to Applicatie
    def check(self, *args, **kwargs):
        return []

    def get_formset(self, request, obj=None, **kwargs):
        return CredentialsFormSet


@admin.register(Applicatie)
class ApplicatieAdmin(admin.ModelAdmin):
    list_display = ("uuid", "client_ids", "label", "heeft_alle_autorisaties")
    readonly_fields = ("uuid",)
    form = ApplicatieForm
    inlines = (
        CredentialsInline,
        AutorisatieInline,
    )

    def get_urls(self) -> list:
        urls = super().get_urls()
        custom_urls = [
            path(
                "<path:object_id>/autorisaties/",
                self.admin_site.admin_view(self.autorisaties_view),
                name="authorizations_applicatie_autorisaties",
            ),
        ]
        return custom_urls + urls

    @property
    def autorisaties_view(self):
        return AutorisatiesView.as_view(admin_site=self.admin_site, model_admin=self,)
