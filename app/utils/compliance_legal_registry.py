"""Versioned legal-reference metadata for WarSOC compliance evidence claims.

This registry records the source and status of a legal reference. It does not
decide whether a law applies to a tenant and it is not a substitute for legal
advice. Compliance controls may reference only IDs defined here.
"""

from __future__ import annotations


LEGAL_REFERENCE_REGISTRY_VERSION = "2026-08-20.phase0"
LEGAL_INSTRUMENT_STATUSES = frozenset({"FINAL", "DRAFT", "SUPERSEDED"})


LEGAL_REFERENCE_REGISTRY = {
    "PK_PECA_2016_CURRENT": {
        "jurisdiction": "Pakistan",
        "tax_regime": None,
        "instrument": "Prevention of Electronic Crimes Act, 2016",
        "instrument_type": "ACT",
        "instrument_status": "FINAL",
        "source_version": "Pakistan Code text amended through 2025",
        "effective_from": None,
        "verified_at": "2026-08-20",
        "source_url": (
            "https://www.pakistancode.gov.pk/pdffiles/"
            "administrator6a061efe0ed5bd153fa8b79b8eb4cba7.pdf"
        ),
        "source_hash": None,
        "verification_state": "OFFICIAL_URL_VERIFIED_HASH_NOT_PINNED",
        "scope_note": (
            "Used only for contextual legal relevance. WarSOC endpoint controls "
            "do not by themselves establish PECA compliance or the section 32 "
            "traffic-data retention obligation."
        ),
    },
    "PK_ETO_2002_SECTIONS_5_6": {
        "jurisdiction": "Pakistan",
        "tax_regime": None,
        "instrument": "Electronic Transactions Ordinance, 2002, sections 5 and 6",
        "instrument_type": "ORDINANCE",
        "instrument_status": "FINAL",
        "source_version": "Pakistan Code official text",
        "effective_from": None,
        "verified_at": "2026-08-20",
        "source_url": (
            "https://pakistancode.gov.pk/pdffiles/"
            "administratordbc98dd49f2df3b1d07bb986dcceb9a3.pdf"
        ),
        "source_hash": None,
        "verification_state": "OFFICIAL_URL_VERIFIED_HASH_NOT_PINNED",
        "scope_note": (
            "Referenced for electronic-record integrity and retention qualities, "
            "not as an automatic admissibility determination."
        ),
    },
    "PK_SALES_TAX_ACT_1990_SECTION_24": {
        "jurisdiction": "Pakistan",
        "tax_regime": "SALES_TAX",
        "instrument": "Sales Tax Act, 1990, section 24",
        "instrument_type": "ACT",
        "instrument_status": "FINAL",
        "source_version": "Updated through 2026-06-30",
        "effective_from": None,
        "verified_at": "2026-08-20",
        "source_url": (
            "https://download1.fbr.gov.pk/Docs/"
            "20267171373418951SalesTaxAct1990updatedupto30.06.2026.pdf"
        ),
        "source_hash": None,
        "verification_state": "OFFICIAL_URL_VERIFIED_HASH_NOT_PINNED",
        "scope_note": (
            "Sales-tax record retention is anchored to the end of the relevant "
            "tax period and may be extended by unresolved proceedings. The current "
            "fixed-day WarSOC policy remains a migration fallback only."
        ),
    },
    "PK_SALES_TAX_RULES_2006_CHAPTER_XIV": {
        "jurisdiction": "Pakistan",
        "tax_regime": "SALES_TAX",
        "instrument": "Sales Tax Rules, 2006, Chapter XIV",
        "instrument_type": "RULES",
        "instrument_status": "FINAL",
        "source_version": "FBR consolidated text updated through 2025-01-01",
        "effective_from": None,
        "verified_at": "2026-08-20",
        "source_url": (
            "https://download1.fbr.gov.pk/Docs/"
            "20251141513138962Sales-Tax-Rules-2006-UpdatedUpto01-01-2025.pdf"
        ),
        "source_hash": None,
        "verification_state": "OFFICIAL_URL_VERIFIED_HASH_NOT_PINNED",
        "scope_note": (
            "Defines electronic-invoicing and licensed-integrator obligations. "
            "WarSOC is an independent evidence platform and is not represented as "
            "an FBR-licensed integrator."
        ),
    },
    "PK_FBR_STGO_01_2026": {
        "jurisdiction": "Pakistan",
        "tax_regime": "SALES_TAX",
        "instrument": "Sales Tax General Order 01 of 2026",
        "instrument_type": "GENERAL_ORDER",
        "instrument_status": "FINAL",
        "source_version": "Issued 2026-03-30",
        "effective_from": "2026-03-30",
        "verified_at": "2026-08-20",
        "source_url": (
            "https://download1.fbr.gov.pk/Docs/2026331133557466STGO01of2026.pdf"
        ),
        "source_hash": None,
        "verification_state": "OFFICIAL_URL_VERIFIED_HASH_NOT_PINNED",
        "scope_note": (
            "Provides current digital-invoice integration and amendment context. "
            "It does not make WarSOC an invoice-submission system or integrator."
        ),
    },
    "PK_FBR_SRO_288_I_2026_DRAFT": {
        "jurisdiction": "Pakistan",
        "tax_regime": "INCOME_TAX",
        "instrument": "S.R.O. 288(I)/2026, Online Integration of Businesses",
        "instrument_type": "DRAFT_RULES_AMENDMENT",
        "instrument_status": "DRAFT",
        "source_version": "Draft published for objections and suggestions",
        "effective_from": None,
        "verified_at": "2026-08-20",
        "source_url": (
            "https://download1.fbr.gov.pk/SROs/2026218112270512SRO288dated18.02.2026.pdf"
        ),
        "source_hash": None,
        "verification_state": "OFFICIAL_URL_VERIFIED_HASH_NOT_PINNED",
        "scope_note": (
            "Tracked for architecture awareness only. It is not the sole authority "
            "for the current Sales Tax POS evidence profile and cannot support a "
            "final-law product claim."
        ),
    },
}


def validate_legal_reference_registry() -> None:
    required = {
        "jurisdiction",
        "tax_regime",
        "instrument",
        "instrument_type",
        "instrument_status",
        "source_version",
        "effective_from",
        "verified_at",
        "source_url",
        "source_hash",
        "verification_state",
        "scope_note",
    }
    for reference_id, reference in LEGAL_REFERENCE_REGISTRY.items():
        missing = required - set(reference)
        if missing:
            raise RuntimeError(
                f"Legal reference {reference_id} is missing fields: {sorted(missing)}"
            )
        if reference["instrument_status"] not in LEGAL_INSTRUMENT_STATUSES:
            raise RuntimeError(
                f"Legal reference {reference_id} has an invalid instrument status"
            )
        if not str(reference["source_url"]).startswith("https://"):
            raise RuntimeError(f"Legal reference {reference_id} must use an HTTPS source")


validate_legal_reference_registry()
