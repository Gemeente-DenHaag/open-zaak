# SPDX-License-Identifier: EUPL-1.2
# Copyright (C) 2019 - 2021 Dimpact
DOC_AUTH_JWT = """
### Autorisatie

Deze API vereist autorisatie.

_Zelf een token genereren_

De tokens die gebruikt worden voor autorisatie zijn [jwt.io][JWT's] (JSON web
token). In de API calls moeten deze gebruikt worden in de `Authorization`
header:

```
Authorization: Bearer <token>
```

Om een JWT te genereren heb je een `client ID` en een `secret` nodig. Het JWT
moet gebouwd worden volgens het `HS256` algoritme. De vereiste payload is:

```json
{
    "iss": "<client ID>",
    "iat": 1572863906,
    "client_id": "<client ID>",
    "user_id": "<user identifier>",
    "user_representation": "<user representation>"
}
```

Als `issuer` gebruik je dus je eigen client ID. De `iat` timestamp is een
UNIX-timestamp die aangeeft op welk moment het token gegenereerd is.

`user_id` en `user_representation` zijn nodig voor de audit trails. Het zijn
vrije velden met als enige beperking dat de lengte maximaal de lengte van
de overeenkomstige velden in de audit trail resources is (zie rest API spec).
"""


DOC_OAS_DIFFERENCES = """
### API specificatie afwijkingen

Afwijkingen in de API specificatie ten opzichte van de referentie API specificatie
zijn aangemerkt met ***AFWIJKING:**
"""


def mark_oas_difference(help_text):
    """
    Indicate in help_text that the feature is a deviation from the reference
    API specification
    """
    return f"***AFWIJKING:** {help_text}"
