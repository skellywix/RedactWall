---
name: valyu
description: Real-time web search plus 36+ specialised/paywalled data sources (SEC filings, PubMed, FRED, patents, academic) through one API with cited answers. For PromptSentinel, use it to pull current NCUA/GLBA/PCI/HIPAA regulatory text, research prospects, and source authoritative tuning data. Wraps the external Valyu skill (needs your API key).
---

# Valyu

Connects the agent to current, authoritative, often-paywalled data instead of stale training data — with a citation trail.

## Install + key (you provide the key; I won't enter credentials)
`npx skills add valyuAI/skills` then set your `VALYU_API_KEY` in the environment yourself.

## PromptSentinel uses
- **Regulatory grounding:** fetch the current text of NCUA / GLBA Safeguards Rule / PCI-DSS / HIPAA requirements when building the regulation templates in `src/templates.js` — so the mappings cite real, dated source, not memory.
- **Prospect research:** credit-union profiles, examiner findings, recent breach news to inform sales/positioning.
- **Detection tuning corpus:** authoritative examples of sensitive-data formats (e.g. real IBAN country structures) to harden `shared/detect.js` validators — using format references, never real PII.

## Best practices (from the skill)
- Be specific about which sources you need (`included_sources=[...]`).
- Use the Answer/context API when you want a cited response, not raw docs.
- Always surface sources to the user — the data is only as trustworthy as the citation.

## Rules
- Cite every regulatory claim with the Valyu source + date; compliance content must be verifiable.
- Never send member data or prompt contents to an external search API.
- API key is yours to manage; I won't paste or store it.
