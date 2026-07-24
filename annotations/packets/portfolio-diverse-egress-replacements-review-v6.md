# Five egress-safe replacement labels for reviewer-a17

- Packet SHA-256: `ec991987a8c87d6928436773ef27cd9a30ca6c4a61d3a3c3b9d2f99d46a89d98`
- Items: 5
- Scope: only the five restrictive-source replacements; the other 59 active contracts are unchanged.
- Human action: approve or correct each proposed label. No model output is present.

## 1. `portfolio-diverse-abstain-08`

**Question:** Which production-ready firmware release and generally available release date does CISA Update B establish for remediating CVE-2025-8286?

**Cutoff:** `2026-07-22T21:30:00+00:00`

**Slice:** `cutoff_or_insufficiency_abstention`

**Authentic evidence:**

  - `abstain-guralp:cisa-experimental-firmware` (cisa-icsa-25-212-01-update-b): For Minimus-based products (including Fortimus and Certimus), experimental firmware release v2.1-29897 introduces authentication for Telnet access. This change requires valid login credentials before allowing access to the Telnet interface, addressing the missing authentication condition described in CVE-2025-8286.
  - `abstain-guralp:cisa-experimental-qualification` (cisa-icsa-25-212-01-update-b): This firmware version provides protection against unauthenticated remote access. As it is an experimental release, users should evaluate it in line with their operational and security requirements before upgrading. If users have any questions, they are encouraged to contact support@guralp.com.

**Proposed structured label:**

  - `portfolio-diverse-abstain-08:reason`: `"predicate_absent"` (cutoff-eligible CISA coordinator evidence)

**Reference answer:** None

**Abstention:** `predicate_absent` — The eligible coordinator record identifies experimental firmware but establishes neither production-ready status nor a release date.

**Authority rationale:** CISA is authoritative for its coordinator record. It records only an experimental firmware identifier and explicitly requires local evaluation; it does not establish a production-ready release date.

**Ambiguity note:** The experimental identifier must not be upgraded into a generally available production release or assigned an unstated release date.

## 2. `portfolio-diverse-authority-07-v4`

**Question:** Which PiCtory action is CISA's coordinator recommendation, and which separate Bookworm release fact does its Update A record as KUNBUS-qualified?

**Cutoff:** `2026-07-22T21:30:00+00:00`

**Slice:** `authority_divergence`

**Authentic evidence:**

  - `authority-kunbus:cisa-pictory-212` (cisa-icsa-25-121-01-initial): Update PiCtory package to version 2.12
  - `authority-kunbus:vendor-qualified-image` (cisa-icsa-25-121-01-update-a): KUNBUS released a new image for Revolution Pi OS Bookworm on 04/30/2025. Users can download the updated image here.

**Proposed structured label:**

  - `portfolio-diverse-authority-07-v4:cisa`: `"update PiCtory to 2.12"` (CISA coordinator recommendation authority)
  - `portfolio-diverse-authority-07-v4:vendor-qualified`: `"KUNBUS released a Revolution Pi OS Bookworm image on 2025-04-30"` (CISA coordinator record of a KUNBUS-qualified release)

**Reference answer:** CISA's coordinator recommendation is to update PiCtory to 2.12; the later coordinator state records the vendor-qualified fact that KUNBUS released a Revolution Pi OS Bookworm image on 2025-04-30. Structured component coverage: [portfolio-diverse-authority-07-v4:cisa="update PiCtory to 2.12"] [portfolio-diverse-authority-07-v4:vendor-qualified="KUNBUS released a Revolution Pi OS Bookworm image on 2025-04-30"]

**Abstention:** `None` — None

**Authority rationale:** The first component is CISA's recommendation; the second is a vendor-qualified release fact recorded by CISA, not independent proof from a KUNBUS source.

**Ambiguity note:** Do not describe the CISA-hosted vendor-qualified release statement as independently verified vendor evidence.

## 3. `portfolio-diverse-authority-08`

**Question:** Which limited vendor-fix scope does CISA's initial ECOVACS state record, and which separate user action does Update A prescribe?

**Cutoff:** `2026-07-22T21:30:00+00:00`

**Slice:** `authority_divergence`

**Authentic evidence:**

  - `authority-ecovacs:initial-vendor-fix` (cisa-icsa-25-135-19-initial): ECOVACS has released software updates for the X1S PRO and X1 PRO OMNI. The remaining affected products will have updates available by May 31, 2025. Devices that support automatic updates will receive system update notifications. ECOVACS has proactively pushed the update to users, ensuring all users will be covered by May 31st. Users can complete the fix by performing the system update.
  - `authority-ecovacs:update-user-action` (cisa-icsa-25-135-19-update-a): ECOVACS has released software updates for all affected devices. Devices that support automatic updates will receive system update notifications. ECOVACS has proactively pushed the update to users, ensuring all users are covered. Users can complete the fix by performing the system update.

**Proposed structured label:**

  - `portfolio-diverse-authority-08:fact-1`: `"updates released for X1S PRO and X1 PRO OMNI"` (CISA initial coordinator record of ECOVACS vendor-fix scope)
  - `portfolio-diverse-authority-08:fact-2`: `"users complete the fix by performing the system update"` (CISA Update A remediation instruction)

**Reference answer:** The initial coordinator state records ECOVACS updates for X1S PRO and X1 PRO OMNI; Update A instructs users to complete the fix by performing the system update. Structured component coverage: [portfolio-diverse-authority-08:fact-1="updates released for X1S PRO and X1 PRO OMNI"] [portfolio-diverse-authority-08:fact-2="users complete the fix by performing the system update"]

**Abstention:** `None` — None

**Authority rationale:** The initial scope is a vendor-fix statement reported in CISA's coordinator record; the completion action is remediation guidance stated in Update A.

**Ambiguity note:** Keep the vendor-qualified update availability distinct from the coordinator document's user-facing remediation instruction.

## 4. `portfolio-diverse-synthesis-06`

**Question:** What update deadline did the initial CISA ECOVACS state give for the remaining affected products, and what complete coverage does Update A establish?

**Cutoff:** `2026-07-22T21:30:00+00:00`

**Slice:** `multi_source_synthesis`

**Authentic evidence:**

  - `synthesis-ecovacs:initial-deadline` (cisa-icsa-25-135-19-initial): ECOVACS has released software updates for the X1S PRO and X1 PRO OMNI. The remaining affected products will have updates available by May 31, 2025. Devices that support automatic updates will receive system update notifications. ECOVACS has proactively pushed the update to users, ensuring all users will be covered by May 31st. Users can complete the fix by performing the system update.
  - `synthesis-ecovacs:update-complete-coverage` (cisa-icsa-25-135-19-update-a): ECOVACS has released software updates for all affected devices. Devices that support automatic updates will receive system update notifications. ECOVACS has proactively pushed the update to users, ensuring all users are covered. Users can complete the fix by performing the system update.

**Proposed structured label:**

  - `portfolio-diverse-synthesis-06:fact-1`: `"remaining affected products were scheduled for updates by 2025-05-31"` (CISA initial-state vendor-fix schedule)
  - `portfolio-diverse-synthesis-06:fact-2`: `"software updates available for all affected devices"` (CISA Update A remediation coverage)

**Reference answer:** The initial state scheduled the remaining affected products for updates by 2025-05-31; Update A records software updates as available for all affected devices. Structured component coverage: [portfolio-diverse-synthesis-06:fact-1="remaining affected products were scheduled for updates by 2025-05-31"] [portfolio-diverse-synthesis-06:fact-2="software updates available for all affected devices"]

**Abstention:** `None` — None

**Authority rationale:** CISA is authoritative for the contents of both coordinator states; the update schedule and coverage remain ECOVACS-qualified.

**Ambiguity note:** This is source-state synthesis and is correlated with, but not the same answer contract as, the separate coverage-change question.

## 5. `portfolio-diverse-synthesis-07`

**Question:** What PiCtory update method does the initial CISA state establish, and what separate Bookworm image release does Update A add?

**Cutoff:** `2026-07-22T21:30:00+00:00`

**Slice:** `multi_source_synthesis`

**Authentic evidence:**

  - `synthesis-kunbus:pictory-cockpit-method` (cisa-icsa-25-121-01-initial): The preferred method for updating to version 2.12 is accomplished through KUNBUS's management UI Cockpit. However, users can also download the update package here.
  - `synthesis-kunbus:bookworm-image` (cisa-icsa-25-121-01-update-a): KUNBUS released a new image for Revolution Pi OS Bookworm on 04/30/2025. Users can download the updated image here.

**Proposed structured label:**

  - `portfolio-diverse-synthesis-07:fact-1`: `"update PiCtory to 2.12 through the Cockpit management UI"` (CISA initial-state PiCtory update method)
  - `portfolio-diverse-synthesis-07:fact-2`: `"new Revolution Pi OS Bookworm image released 2025-04-30"` (CISA Update A vendor-fix record)

**Reference answer:** The initial state says to update PiCtory to 2.12 through the Cockpit management UI; Update A records a new Revolution Pi OS Bookworm image released on 2025-04-30. Structured component coverage: [portfolio-diverse-synthesis-07:fact-1="update PiCtory to 2.12 through the Cockpit management UI"] [portfolio-diverse-synthesis-07:fact-2="new Revolution Pi OS Bookworm image released 2025-04-30"]

**Abstention:** `None` — None

**Authority rationale:** CISA is authoritative for the contents of each coordinator state; the Bookworm release remains explicitly KUNBUS-qualified.

**Ambiguity note:** This is source-state synthesis from one public coordinator, not independent cross-publisher corroboration.
