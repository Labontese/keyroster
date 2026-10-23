# Phase 3: Linux Agent and Revocation - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-10-23
**Phase:** 03-linux-agent-and-revocation
**Areas discussed:** Tillit och enrollment, Agenten på värden, Spärrar och tider, Certifikat, nöd och plattformar

The questions were asked in Swedish with the option text from 03-DISCUSS-PREP.md; the owner's answers are quoted verbatim. Every answer was the recommended option.

## Todos

| Option | Selected |
|--------|----------|
| Fas 2-uppföljningar i kod (Rek.) | ✓ |
| Två negativa tester (Rek.) | ✓ |
| Dokumenträttelser (Rek.) | ✓ |
| Binda katalogen till installationen | (decided through Q22 instead) |

---

## Tillit och enrollment

### Q1 root ceremony

| Option | Selected |
|--------|----------|
| En v4-ceremoni för båda | ✓ |
| TEST root C nu, v4 senare |  |
| Två riktiga ceremonier |  |

**User's choice:** "En v4-ceremoni för båda (Rek.)"

### Q3+Q18 agent identity and AGENT-01 pinning

| Option | Selected |
|--------|----------|
| Självsignerat + pinna TLS-rot | ✓ |
| Agent-CA på servern |  |
| Pinna serverns egen nyckel |  |

**User's choice:** "Självsignerat + pinna TLS-rot (Rek.)"

### Q4 what hosts receive

| Option | Selected |
|--------|----------|
| Hela admin-signerade katalogen | ✓ |
| Utdrag per värd, signerat av signern |  |

**User's choice:** "Hela admin-signerade katalogen (Rek.)"

### Q22 installation binding

| Option | Selected |
|--------|----------|
| Installations-ID nu | ✓ |
| Lämna till fas 4 |  |
| Agenten minns första katalogen |  |

**User's choice:** "Installations-ID nu (Rek.)"

---

## Agenten på värden

### Q2 process model

| Option | Selected |
|--------|----------|
| Hämtare + applicerare | ✓ |
| En root-daemon |  |

**User's choice:** "Hämtare + applicerare (Rek.)"

### Q8 self-test depth and probe account

| Option | Selected |
|--------|----------|
| Fullt test, runbooken skapar kontot | ✓ |
| Fullt test, agenten skapar kontot |  |
| Bara sshd och värdcert nu |  |

**User's choice:** "Fullt test, runbooken skapar kontot (Rek.)"

### Q9+Q10 unsupported or conflicting sshd config

| Option | Selected |
|--------|----------|
| Vägra och förklara | ✓ |
| Skriv över eller slå ihop |  |

**User's choice:** "Vägra och förklara (Rek.)"

### Q19 Phase 2 hand-set hosts

| Option | Selected |
|--------|----------|
| Ta över exakt fas 2-upplägg | ✓ |
| Du städar först |  |

**User's choice:** "Ta över exakt fas 2-upplägg (Rek.)"

---

## Spärrar och tider

### Q6 revoking a person, host or machine

| Option | Selected |
|--------|----------|
| Signern spärrar alla | ✓ |
| CLI:n listar serienummer |  |
| Bara inaktivera |  |

**User's choice:** "Signern spärrar alla (Rek.)"

### Q14 acceptable revocation delay

| Option | Selected |
|--------|----------|
| Cirka 1 minut | ✓ |
| Cirka 5 minuter |  |
| Under 15 sekunder |  |

**User's choice:** "Cirka 1 minut (Rek.): poll 60 s ± 10 s, KRL re-signed hourly, host alert at 24 h, server flags hosts silent 3 min"

### Q15 host groups per host

| Option | Selected |
|--------|----------|
| Exakt en i fas 3 | ✓ |
| Flera |  |

**User's choice:** "Exakt en i fas 3 (Rek.)"

### Q20 REVOKE-01 CLI or UI (requirement change)

| Option | Selected |
|--------|----------|
| CLI nu, UI i fas 4 | ✓ |
| En spärrsida redan i fas 3 |  |

**User's choice:** "CLI nu, UI i fas 4 (Rek.) — owner approves rewording REVOKE-01"

---

## Certifikat, nöd och plattformar

### Q5 break-glass and sudo

| Option | Selected |
|--------|----------|
| Match User + sudo m. lösenord | ✓ |
| Match User + ingen sudo |  |
| Match User + sudo utan lösenord |  |

**User's choice:** "Match User + sudo m. lösenord (Rek.)"

### Q7 CA rotation

| Option | Selected |
|--------|----------|
| Två ceremonier | ✓ |
| Tre ceremonier |  |

**User's choice:** "Två ceremonier (Rek.)"

### Q12 machine identities

| Option | Selected |
|--------|----------|
| Admin-signerade poster | ✓ |
| Bara via en värds agent |  |
| Admin utfärdar för hand |  |

**User's choice:** "Admin-signerade poster (Rek.)"

### Q13 host certificates

| Option | Selected |
|--------|----------|
| 30 dagar, namn admin skriver | ✓ |
| 7 dagar |  |
| 90 dagar |  |

**User's choice:** "30 dagar, namn admin skriver (Rek.)"

### Q11 @cert-authority patterns

| Option | Selected |
|--------|----------|
| Exakta värdnamn | ✓ |
| Jokertecken per värdgrupp |  |
| Alla värdar (*) |  |

**User's choice:** "Exakta värdnamn (Rek.)"

### Q16 platforms

| Option | Selected |
|--------|----------|
| Breda golvet | ✓ |
| Bara det du har |  |

**User's choice:** "Breda golvet (Rek.)"

### Q17+Q21 RHEL 8 and FIPS (requirement change)

| Option | Selected |
|--------|----------|
| Skriv om till RHEL 9+, ej FIPS | ✓ |
| Stöd RHEL 8 och FIPS |  |

**User's choice:** "Skriv om till RHEL 9+, ej FIPS (Rek.)"

### Dogfood host versions

| Option | Selected |
|--------|----------|
| Zima Ubuntu 26.04, PVE 8 |  |
| Zima Ubuntu 26.04, PVE 9 |  |
| Jag vet inte, kolla du | ✓ |

**User's choice:** "Jag vet inte, kolla du — Claude read Proxmox VE 9.2.18 on Debian 13 (OpenSSH 10.0p2); zima offline, seen as Ubuntu 26.04.1 with OpenSSH 10.2p1 earlier the same day"

---

## Claude's Discretion

Join-token format and lifetime, fetcher/applier IPC, drop-in names and layout, heartbeat payload, KRL manifest format and namespace, new leaf kinds and their verify rules, plan decomposition.

## Deferred Ideas

- A per-host directory extract (revisit before several teams share an installation).
- Several host groups per host.
- A revoke page in the web UI (Phase 4).
- A P-256 CA generation for RHEL in FIPS mode.
