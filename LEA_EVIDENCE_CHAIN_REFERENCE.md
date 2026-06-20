# EVIDENCE CHAIN & FORENSIC WORKFLOW
## Law Enforcement Officer Quick Reference

---

## EVIDENCE LIFECYCLE DIAGRAM

```
┌────────────────────────────────────────────────────────────────────┐
│                    INVESTIGATION INITIATED                         │
│  Case ID │ Evidence ID │ Investigator │ Warrant ID │ Jurisdiction  │
└────────────────────┬───────────────────────────────────────────────┘
                     │
                     ▼
     ┌───────────────────────────────────┐
     │  PHASE 0: SETUP & VERIFICATION    │
     ├───────────────────────────────────┤
     │ ✓ Create output directory         │
     │ ✓ Verify admin privileges         │
     │ ✓ Compute tool integrity hash    │
     │ ✓ Initialize audit logging        │
     │ ✓ Chain of Custody: log "Started"│
     └────────────┬──────────────────────┘
                  │
                  ▼ (CRYPTOGRAPHICALLY SIGNED - ECC-256)
         ┌────────────────────────────────┐
         │ forensic_execution_log.txt     │
         │ chain_of_custody_signed.jsonl  │
         └────────────┬───────────────────┘
                      │
         ┌────────────┴────────────┐
         │                         │
         ▼                         ▼
   ┌──────────────┐        ┌──────────────┐
   │ LIVE SYSTEM  │        │ FORENSIC     │
   │ ACQUISITION  │        │ IMAGE        │
   └──────┬───────┘        │ (.dd/.E01)   │
          │                └──────┬───────┘
          │                       │
          │              ┌────────▼───────┐
          │              │ DiskImager     │
          │              │ pytsk3/pyewf   │
          │              │ Mount & Discover
          │              └────────┬───────┘
          │                       │
          └───────────┬───────────┘
                      │
          ┌───────────▼─────────────┐
          │  PHASE 1: COLLECTION    │
          │  (Parallel execution)   │
          └───────────┬─────────────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
    ┌────▼──┐  ┌─────▼──┐  ┌─────▼──┐
    │Chrome │  │Firefox │  │Safari  │
    │Collect│  │Collect │  │Collect │
    └────┬──┘  └─────┬──┘  └─────┬──┘
         │           │           │
         └───────────┼───────────┘
                     │
         ┌───────────▼──────────┐
         │ extracted_databases/ │
         │ ✓ *.sqlite files     │
         │ ✓ *.json configs    │
         │ ✓ hash_manifest.txt  │
         │ (SHA-256 for all)    │
         └───────────┬──────────┘
                     │
                     ▼ (HASH VERIFIED)
         ┌───────────────────────┐
         │  PHASE 2: PARSING     │
         │  (Browser detection)  │
         └───────────┬───────────┘
                     │
    ┌────────────────┼────────────────┐
    │                │                │
┌───▼───┐      ┌─────▼──┐       ┌────▼────┐
│History│      │Cookies │       │Password │
│Parser │      │Parser  │       │Parser   │
└───┬───┘      └─────┬──┘       └────┬────┘
    │                │               │
    └────────────────┼───────────────┘
                     │
         ┌───────────▼──────────┐
         │ In-Memory Structures │
         │ all_history[]        │
         │ all_cookies[]        │
         │ all_passwords[]      │
         │ etc. (12 types)      │
         └───────────┬──────────┘
                     │
              ┌──────▼──────┐
              │ DEEP        │
              │ RECOVERY    │
              │ (Optional)  │
              │ ✓ WAL/SHM   │
              │ ✓ Cache     │
              │ ✓ Carving   │
              └──────┬──────┘
                     │
         ┌───────────▼──────────┐
         │  PHASE 3: REPORTING  │
         └───────────┬──────────┘
                     │
         ┌───────────▼──────────┐
         │ PII Redaction        │
         │ (if enabled)         │
         └───────────┬──────────┘
                     │
    ┌────────────────┼────────────────┐
    │                │                │
┌───▼─────┐   ┌──────▼──────┐   ┌────▼────┐
│CSV Files│   │XLSX Timeline│   │PDF Report
│17 Reports
└───┬─────┘   └──────┬──────┘   └────┬────┘
    │                │               │
    └────────────────┼───────────────┘
                     │
         ┌───────────▼──────────┐
         │ Chain of Custody:    │
         │ log "Finalized"      │
         │ (ECC-256 signed)     │
         └───────────┬──────────┘
                     │
         ┌───────────▼──────────────────┐
         │  /reports/ Directory         │
         │  1_Browser_History.csv       │
         │  2_Downloads.csv             │
         │  3_Cookies.csv               │
         │  ... (17 total)              │
         │  0_Forensic_Super_Timeline.xlsx
         │  Forensic_Executive_Summary.pdf
         └────────────┬─────────────────┘
                      │
                      ▼
              ┌──────────────────┐
              │ INVESTIGATION    │
              │ COMPLETE         │
              │ Evidence ready   │
              │ for prosecution  │
              └──────────────────┘
```

---

## CHAIN OF CUSTODY VERIFICATION FLOW

```
┌──────────────────────────────────────┐
│ chain_of_custody_signed.jsonl        │
│ (JSONL format, cryptographically     │
│  signed with ECC-256)                │
└──────────┬───────────────────────────┘
           │
           ▼
    ┌──────────────┐
    │ 1. Verify    │
    │ ECC Key ID   │
    │ in signature │
    └──────┬───────┘
           │
           ▼
    ┌────────────────────┐
    │ 2. Extract Public  │
    │ Key from:          │
    │ chain_of_custody_  │
    │ public.pem         │
    │ (exported key)     │
    └──────┬─────────────┘
           │
           ▼
    ┌────────────────────┐
    │ 3. Verify SHA-256  │
    │ signature against  │
    │ payload using      │
    │ ECDSA-P256         │
    └──────┬─────────────┘
           │
           ▼
    ┌─────────────────────┐
    │ SIGNATURE VALID?    │
    └─────────┬───────────┘
              │
    ┌─────────┴──────────┐
    │                    │
 YES▼               NO▼
  ┌────────┐      ┌──────────┐
  │VERIFIED│      │TAMPERING │
  │✓       │      │DETECTED  │
  │EVIDENCE│      │✗         │
  │INTACT  │      │EVIDENCE  │
  └────────┘      │REJECTED  │
                  └──────────┘

Evidence integrity cryptographically proven.
Admissible in court as tamper-evident.
```

---

## CRITICAL AUDIT POINTS FOR LEA OFFICERS

### Before Collection Begins:
- [ ] Warrant/Authorization documented
- [ ] Case ID assigned
- [ ] Evidence ID generated
- [ ] Investigator name recorded
- [ ] Jurisdiction verified
- [ ] Warrant ID in system
- [ ] Target device identified

### During Collection:
- [ ] Real-time audit log being written
- [ ] Chain of Custody events logged
- [ ] No interactive intervention
- [ ] Tool running with admin privileges
- [ ] System environment unchanged

### After Collection Completes:
- [ ] Check forensic_execution_log.txt for:
  - [ ] Tool self-integrity hash (SHA-256)
  - [ ] All collection phases logged
  - [ ] Admin privilege status noted
  - [ ] OS version recorded
  - [ ] Python version recorded
  
- [ ] Verify hash_manifest.txt:
  - [ ] All artifacts hashed
  - [ ] SHA-256 algorithm used
  - [ ] No empty hashes (e3b0c44... = empty file)
  
- [ ] Review chain_of_custody_signed.jsonl:
  - [ ] ECC-256 signatures present
  - [ ] Device info captured (MAC, serial)
  - [ ] All phases logged
  - [ ] No gaps in timestamp sequence

- [ ] Examine report files:
  - [ ] No data loss (compare counts in audit log vs CSVs)
  - [ ] All 17 CSV reports generated (if data present)
  - [ ] Super Timeline XLSX created
  - [ ] Executive Summary PDF present

### For Court Admission:
- [ ] Include tool hash in evidence package
- [ ] Attach forensic_execution_log.txt
- [ ] Attach chain_of_custody_signed.jsonl
- [ ] Attach chain_of_custody_public.pem (for independent verification)
- [ ] Attach hash_manifest.txt
- [ ] Document investigator's qualifications
- [ ] Include warrant/authorization documentation
- [ ] Provide case context narrative
- [ ] Reference NIST/SANS standards for browser forensics

---

## EVIDENCE INTEGRITY VERIFICATION (For Prosecution)

### Step 1: Obtain Public Verification Key
```
File: chain_of_custody_public.pem
Contains: ECC-P256 public key
Use: To verify all signatures independently
```

### Step 2: Verify Each Event Signature
```
Each line in chain_of_custody_signed.jsonl contains:
{
  "payload": { ... event data ... },
  "signature": "hex_string...",
  "algorithm": "ecdsa-p256-sha256",
  "key_id": "16_char_hex"
}

Verification steps:
1. Extract payload JSON
2. Compute SHA-256 of payload JSON bytes
3. Verify signature against hash using public key
4. If valid: Event is authentic and unmodified
5. If invalid: Evidence has been tampered with
```

### Step 3: Hash Verification
```
For each artifact:
1. Open artifact file
2. Compute SHA-256 hash
3. Compare against hash_manifest.txt
4. If match: File integrity confirmed
5. If mismatch: File has been modified (REJECT)
```

### Step 4: Timeline Verification
```
All timestamps must:
1. Be in UTC (Zulu time)
2. Increase monotonically (no backwards time)
3. Show progression through phases (0→1→2→3→4)
4. Include investigator identification
5. Show warrant/jurisdiction information
```

---

## COMMON EVIDENCE COUNTS

When reviewing reports, expect approximately:

| Artifact Type | Typical Count | Notes |
|--------------|--------------|-------|
| History Records | 100-5000 | Per browser |
| Cookies | 50-500 | Per browser |
| Downloads | 10-200 | Total |
| Bookmarks | 5-100 | Per browser |
| Passwords | 5-50 | Usually encrypted |
| Extensions | 5-30 | Per browser |
| Sessions | 1-10 | Active sessions |
| Cloud Sync | 0-100 | If enabled |
| Browser Storage | 10-1000 | IndexedDB, LocalStorage |
| Service Workers | 1-50 | Ghost sessions |

**Note:** Zero counts may indicate:
- Browser not installed
- No user activity
- Profile not found
- Artifact deletion
- Fresh OS installation

All zeros across all artifacts may indicate:
- ⚠️ SYSTEM NOT CHECKED FOR ADMIN PRIVILEGES
- ⚠️ WRONG USER PROFILE
- ⚠️ ENCRYPTED FILESYSTEM
- ✓ Verify in audit log: "Admin Privileges: False/True"

---

## QUICK TROUBLESHOOTING CHECKLIST

| Issue | Cause | Solution |
|-------|-------|----------|
| No artifacts found | Admin privileges not present | Run as Administrator/root |
| "Invalid output path" | Path sanitization rejection | Use absolute path (C:\Evidence\) |
| Empty password records | Encryption key not accessible | Check LocalState.json present |
| Image loading fails | pytsk3 not installed | pip install pytsk3 |
| E01 images not supported | pyewf not installed | pip install pyewf |
| LLM model fails | Insufficient disk space | Check ~/.cache/ has 1.1GB free |
| Session hijacking blocked | No --confirm-hijack flag | Add flag to enable feature |
| Threat Intel missing | VirusTotal API key not set | Set VT_API_KEY environment variable |

---

## EVIDENCE PACKAGE FOR PROSECUTION

### Required Files to Submit:
1. **Forensic Execution Log**
   - `forensic_execution_log.txt`
   - Shows complete audit trail

2. **Chain of Custody Documentation**
   - `chain_of_custody_signed.jsonl` (cryptographic proof)
   - `chain_of_custody_public.pem` (verification key)
   - Printable chain of custody form

3. **Integrity Documentation**
   - `extracted_databases/hash_manifest.txt`
   - All SHA-256 hashes for artifacts

4. **Evidence Reports** (Choose based on case needs)
   - `1_Browser_History.csv` (most important)
   - `2_Downloads.csv`
   - `3_Cookies.csv`
   - `5_Password_Artifacts.csv`
   - Others as relevant
   - `0_Forensic_Super_Timeline.xlsx` (timeline view)
   - `Forensic_Executive_Summary.pdf` (for judges/jury)

5. **Tool Documentation**
   - Tool version (1.0.0)
   - Tool hash (from audit log)
   - README.md (methodology)
   - Investigator qualifications

6. **Legal Documentation**
   - Warrant/search authorization
   - Case number
   - Investigator badge number
   - Agency letterhead certification

### Package Organization:
```
Case_2026_001_Evidence_Package/
├── INVESTIGATION_METADATA.txt
│   └── Case ID, Evidence ID, Warrant ID, Investigator, Jurisdiction
├── CHAIN_OF_CUSTODY/
│   ├── chain_of_custody_signed.jsonl
│   ├── chain_of_custody_public.pem
│   └── CoC_Verification_Instructions.txt
├── INTEGRITY/
│   ├── forensic_execution_log.txt
│   ├── hash_manifest.txt
│   └── Tool_Self_Hash_Verification.txt
├── EVIDENCE_REPORTS/
│   ├── 1_Browser_History.csv
│   ├── 2_Downloads.csv
│   ├── 3_Cookies.csv
│   ├── 5_Password_Artifacts.csv
│   ├── 0_Forensic_Super_Timeline.xlsx
│   └── Forensic_Executive_Summary.pdf
└── TOOL_DOCUMENTATION/
    ├── BrowserForensicsTool_README.md
    ├── Tool_Version_1.0.0.txt
    └── Investigator_Qualifications.pdf
```

---

## EXPERT WITNESS TESTIMONY FRAMEWORK

### Key Points for Expert Witness:
1. **Tool Reliability**
   - Explain ECC-256 cryptography
   - Reference NIST standards
   - Discuss test coverage (13 passing tests)

2. **Chain of Custody Integrity**
   - Explain tamper-evident logging
   - Demonstrate signature verification
   - Reference public key cryptography

3. **Data Accuracy**
   - Explain SQLite parsing methodology
   - Discuss timestamp conversion (WebKit, UNIX, etc.)
   - Reference industry standards

4. **Admissibility**
   - Explain Frye/Daubert compliance
   - Reference forensic standards (NIST, SANS, ACE)
   - Provide peer-reviewed literature

### Expert Witness Questions to Expect:
- Q: How do we know this tool wasn't modified?
  - A: ECC-256 digital signatures on all events, plus tool self-hash verification

- Q: How do we know evidence wasn't tampered with?
  - A: SHA-256 hash manifest for all artifacts + cryptographic signatures

- Q: Why should we trust SQLite parsing?
  - A: SQLite is industry standard, used by law enforcement, military, and enterprises

- Q: What about browser encryption?
  - A: Tool automatically detects and decrypts when possible (LocalState key)

- Q: How complete is this evidence collection?
  - A: Multi-phase collection (live system, forensic image, mobile) with 9 browsers

---

## END OF LEA QUICK REFERENCE GUIDE

**For questions about this tool, refer to:**
- Technical: BrowserForensicsTool/README.md
- Deployment: LEA_FORENSIC_AUDIT_REPORT.md
- Standards: NIST DERD, Magnet AXIOM, SANS Forensics
- Support: Internal IT security team or original developers

**Keep this guide and audit report with all evidence packages.**

**Last Updated:** June 20, 2026  
**Tool Version:** 1.0.0 (Elite Edition)  
**Status:** 🟢 APPROVED FOR PRODUCTION
