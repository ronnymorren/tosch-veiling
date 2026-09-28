# Automatische veilingverlenging

Een geaccepteerd bod bij **meer dan 0 en maximaal 5 seconden** resterende tijd
zet de eindtijd op **10 seconden na serveracceptatie**. De server controleert
de tijd na verkrijging van de veilingrij-lock. De regel kan onbeperkt herhalen.
Bod en eindtijd worden samen gecommit; mislukte of te late biedingen verlengen niet.

## Testomgeving

De tests laden geen `.env` en gebruiken uitsluitend PostgreSQL op
`127.0.0.1:55439`, database `veiling_extension_test`. Ze wissen daarin de
testveilingen. Gebruik hier uitsluitend een wegwerpcontainer:

```sh
docker run --rm -d --name veiling-extension-test -p 127.0.0.1:55439:5432 -e POSTGRES_HOST_AUTH_METHOD=trust postgres:17-alpine
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt tzdata
.venv/Scripts/python.exe tests/test_extension.py
node --test tests/countdown.test.mjs
node tests/browser.mjs
docker stop veiling-extension-test
```

De browsertest gebruikt Chrome op het standaard Windows-pad en start zelf
een lokale FastAPI-fixture op een vrije poort. Geen echte accounts of mails.
Voer de database- en browsertests na elkaar uit; ze delen de testdatabase.

## Controles

- Grenzen 5.000001, 5, 4.999999, 0.000001, 0 en -0.000001 seconden.
- Herhaalde verlenging en geldige biedingen buiten het verlengingsvenster.
- Ongeldige bedragen, onvoldoende bod, domeinbeperking en beëindigde veilingen.
- Zes gelijktijdige gelijke biedingen: precies één geaccepteerd bod.
- Geforceerde databasefout: bod en eindtijd beide teruggedraaid.
- Poll en afloopmail-vangnet wachten aantoonbaar op een ongecommit bod
  (`pg_stat_activity`), lezen daarna de verlengde eindtijd en mailen niet te vroeg.
- Gelijktijdige afloopcontroles claimen de afloopmail precies één keer.
- Serverklok, oude responses, wachten bij nul en hervatten na verlenging.
- Twee echte browsercontexten, Amsterdam/New York, desktop/mobiel,
  overzicht bijwerken, herhaald bieden en weigeren na definitieve afloop.

## Uitrol

Geen schemawijziging vereist. De regel geldt voor alle nog lopende veilingen.
Ververs reeds geopende veilingpagina's na uitrol zodat ook de nieuwe
kloksynchronisatie wordt geladen.
