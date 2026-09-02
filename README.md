# drive-external-share-audit

A Google Apps Script that inventories files in your Drive corpus, plus any shared drives you explicitly configure, and reports which of them are shared with people outside your organization.

It runs on two OAuth scopes, neither of which permits reading file contents. It makes no outbound requests to third-party services, sends no mail, and does not modify audited files or their permissions — its only writes go to the Google Sheet it is bound to, alongside a second tab stating how complete the run actually was. It does of course call Google's Drive API; that is the whole job.

Built and maintained by [RESIDENT.NGO](https://resident.ngo), a digital security organization supporting civil society, journalists, activists and human rights defenders.

**Topics:** `google-apps-script` `google-drive` `google-workspace` `drive-api` `security-audit` `external-sharing` `data-exposure` `least-privilege` `oauth2` `digital-security` `civil-society` `nonprofit`

---

## Why this exists

There is no way to ask Google Drive "which of my files are shared with someone outside my domain?" The pieces that look like they should answer it do not:

- **Drive search** supports `to:person@example.com`, one address at a time. There is no domain wildcard and no negation, so `-to:*@yourdomain.org` is not expressible.
- **Admin console audit logs** and the **security investigation tool** are event-based. They record sharing *changes* that were logged, within a retention window, and they over-report: a share to an internal group is flagged as external even when the group has no external members, and published Sites and deleted files appear too. A share revoked last month still shows up. They cannot tell you current state.
- **Security dashboard → File exposure** gives aggregate counts, is edition-dependent, and inherits the same accuracy problems.
- **GAM7 / GAMADV-XTD3** genuinely does the job and is the right tool for a domain-wide answer. It also needs a GCP project, a service account, domain-wide delegation and super-admin rights, and it produces a credential that can read every user's Drive.

That leaves a real gap: one person auditing their own Drive, with no admin rights and no long-lived credential. This script fills that gap. Because it holds nothing but the running user's own consent, it can be handed to colleagues to run against their own accounts without anyone gaining access to anyone else's data.

It is not a substitute for GAM. If the question is "what is our organization exposing," use GAM. If the question is "what am *I* exposing," use this.

---

## What it reports

For every file visible to the running account, each permission held by:

- a user or group outside your domains
- an entire external domain
- anyone with the link, or anyone including Google search

plus files owned by outsiders, grants to internal groups (whose membership the API will not expand), and files whose sharing state could not be read at all.

Results include whether each grant is **direct** or **inherited**, which determines where remediation has to happen.

---

## Repository layout

```
appsscript.json   manifest - pins the two OAuth scopes and the Drive v3 advanced service
Code.gs           the audit
LICENSE           MIT
README.md         this file
```

`Code.gs` ships unconfigured: `INTERNAL_DOMAINS` is a placeholder and `SHARED_DRIVE_IDS` is empty. Fill both in your own copy, and keep in mind that a configured copy contains your tenant's domain list and shared drive IDs — do not commit it back to a public fork.

---

## Setup

### 1. Create the host spreadsheet

Make a new Google Sheet in the account you want to audit. The script lives inside it and writes results into it.

Do not put this sheet in a shared folder. Its contents are a map of your account's exposure: file names, file IDs, direct links, owner addresses and external collaborator addresses. Share it only with people entitled to that map.

### 2. Open the script editor

In the sheet: **Extensions → Apps Script**.

### 3. Name the project before anything else

Click **Untitled project** at the top left and give it a real name, for example `drive-external-share-audit`.

This matters more than it looks. Once you authorize the script it appears permanently in your Google Account under **Data & privacy → Third-party apps & services**, and it appears there under the project name. A project left as "Untitled project" shows up in that list as an unnamed application holding Drive metadata access on your account — indistinguishable at a glance from something malicious, and impossible to reason about six months later when you are reviewing what has access to what. It is also the name you will search for when you revoke access.

If you audit several accounts, name each project so you can tell them apart.

### 4. Show the manifest

**Project Settings** (gear icon) → tick **Show "appsscript.json" manifest file in editor**.

This is not cosmetic. Apps Script infers scopes when you do not declare them, and it can infer broader access than a script needs — Google's own guidance is to set scopes explicitly rather than rely on inference. Declaring them yourself is what holds the script to metadata-only.

### 5. Paste both files

Back in **Editor**:

- click `appsscript.json`, replace its entire contents with this repository's `appsscript.json`
- click `Code.gs`, replace its entire contents with this repository's `Code.gs`
- save

Check the **Services** panel in the left sidebar. It should list **Drive (v3)**. If it does not, click **Services +**, add **Google Drive API**, set the version to **v3** — the panel and the manifest edit the same setting, but going through the panel also enables the underlying API in the script's Cloud project.

### 6. Configure your domains

```javascript
const INTERNAL_DOMAINS = ['yourdomain.org'];
const SEMI_TRUSTED_DOMAINS = [];
```

Take this list from **Admin console → Account → Domains → Manage domains**, not from the Drive sharing dialog. The sharing dialog labels everyone "at *primary domain*" regardless of which domain in the tenant their address actually belongs to, so a colleague whose address is `@contractors.yourdomain.org` is displayed as being at `yourdomain.org`. Trusting the dialog produces false positives — including, memorably, flagging yourself as external.

Every classification in the report rests on these two lists. A tenant domain missing from `INTERNAL_DOMAINS` appears as external: a false positive you will notice immediately. An outside domain wrongly added to it is suppressed from every future report: a false negative you never will.

`SEMI_TRUSTED_DOMAINS` exists for that second risk. Domains listed there are reported as `semi-trusted-*` rather than `external-*` — acknowledged as legitimate, but still visible. Use it for contractor domains and subsidiaries where access is expected yet worth reviewing, instead of making that access disappear.

Both lists are printed in the `_info` tab, so anyone reading the report can see what was treated as internal.

### 7. Configure your shared drives

```javascript
const SHARED_DRIVE_IDS = ['0AJ...', '0AB...'];
```

**Leaving this empty means shared drives are not audited.** See the section below for why the script cannot find them for you, and why an empty list is not a clean result.

To get an ID: open the shared drive in Drive and copy it from the URL, `https://drive.google.com/drive/folders/<ID>`. Shared drive IDs begin with `0A`. If you have GAM available, `gam print teamdrives` lists them.

### 8. Optionally set the timezone

Tab names use the script timezone, which the manifest sets to `Etc/UTC`. Change `timeZone` in `appsscript.json` to your own zone (`Europe/Vilnius`, `Europe/Zurich`) if you would rather they read in local time.

### 9. Run it, and read the consent screen

Select `startNewAudit` from the function dropdown and click **Run**.

You will be asked to authorize. Because `drive.metadata.readonly` is a restricted scope on an unverified internal project, you will probably need **Advanced → Go to *project name* (unsafe)**. That warning is expected for a script you installed yourself and have not submitted to Google for verification.

Then read the consent screen. It should ask for exactly two things:

- see information about your Google Drive files
- see, edit, create and delete only the specific Google Drive file used with this application

It must **not** offer to see, edit, create or delete **all** of your Drive files, and it must not mention downloading file content. If it does, the manifest did not take effect. Cancel, fix step 5, and grant nothing until the screen is right.

This screen is your only real verification that the scope restriction worked. It takes five seconds.

### 10. Run until it finishes

Apps Script terminates any execution at six minutes. The script stops itself at five, saves its position and reports:

```
Paused: 1163 files, 440 findings. Run continueAudit().
```

Run `continueAudit` for each pause. `auditStatus` reports progress without changing anything. Shared drive stages are slower than My Drive because each file there costs its own API call, so a large shared drive may need several passes.

Do not run `startNewAudit` again to resume — it starts a fresh audit in new tabs.

### 11. Read the `_info` tab first

Two tabs are created per run:

```
2026-09-02-16:41         findings
2026-09-02-16:41_info    coverage statement
```

Read the coverage statement before you read the findings. It tells you whether the report can be trusted, and names what it could not see.

### 12. Revoke when you are done

**myaccount.google.com → Data & privacy → Third-party apps & services**, find the project by the name you gave it in step 3, remove access.

The grant persists indefinitely otherwise. A standing metadata-read token over your entire Drive is not something to leave active between quarterly audits. Re-authorizing next time is one click.

---

## Why shared drive IDs must be listed by hand

Two separate API facts force this, and both are worth understanding before you decide the empty default is fine.

**Discovering shared drives requires a scope that can read your files.** The Drive API method that lists shared drives, `drives.list`, accepts only the `drive` and `drive.readonly` scopes. It does not accept `drive.metadata.readonly`. Both of the scopes it does accept grant the ability to download file content. So making the script find your shared drives automatically would mean granting an audit tool the power to read every document it inspects — including, on a typical civil society Drive, the documents most worth protecting. That is a bad trade for convenience, so the script does not make it.

**Trash does not revoke access, so trash is scanned.** Google states that only the file owner can trash a file, and that other users can still access it in the owner's trash until it is permanently deleted. A trashed file keeps its permission list intact. An audit that filters trash out would therefore hide live external access — and hide it in exactly the place people are most likely to believe they have already dealt with it, since moving something to Trash feels like deleting it. Only permanent deletion ends the access; Google is equally explicit that after a permanent delete, anyone the file was shared with loses access.

Trashed items are reported like any other, with a `trashed` column so you can filter them, and counted separately in the `_info` tab. If you want a triage shortcut: sort by that column and look at anything with an `external-*` finding first.

**Published shares are hidden by default.** A permission can belong to an additional *view* rather than to the file. Permissions in the `published` view — role `publishedReader`, covering anything put out through Publish to web — are not returned at all unless the request sets `includePermissionsForView: 'published'`. This script sets it on both `Files.list` and `Permissions.list`, the latter because owned My Drive files take the embedded fast path and never reach the former's fallback. Without it, published exposure is invisible to the audit.

**Shared drive files carry no ACL in the ordinary file listing.** Google documents the `permissions` field of a file as populated only when the requesting user can share it, and never populated for items in shared drives. The same applies to `owners`, `shared` and `ownedByMe`. A scanner that reads only that field returns *silently empty results* for all shared drive content — the worst failure an audit can have, because a clean report over an unexamined corpus looks exactly like a clean report. This script therefore calls `Permissions.list` per file for shared drive items, which needs no extra scope but does cost an API call each.

There is a third reason to name the drives explicitly, independent of the API. **A shared drive's own membership is a separate object from any file in it.** Someone added as a Manager or Content Manager on the drive has access to everything inside it, and that grant appears on no individual file's sharing dialog. For each ID you list, the script audits the drive's own ACL as its own stage, tagged `drive-root:<id>`.

To be precise about what that buys you: drive membership *does* also surface on each descendant file, as an inherited permission with `permissionType: member`, so the drive-root stage is not the only way to see it. What it gives you is the grant recorded once at its actual source instead of once per file, an authoritative membership list, coverage of drives that contain no files, and remediation pointed at the drive's member list rather than at a file's sharing dialog where the grant cannot be removed at all.

The consequence to internalize: **an empty `SHARED_DRIVE_IDS` produces a report with no shared drive findings, which is not the same as a report showing no shared drive exposure.** The `_info` tab says `NONE CONFIGURED` for exactly this reason. Silence is not evidence.

Finally, you can only list drives you are a member of. Shared drives you are not in are invisible to you no matter what you configure — that is a question only a domain-wide audit can answer.

---

## Understanding the output

### Columns

| Column | Meaning |
|---|---|
| `scope` | Which stage produced the row: `user` (My Drive and shared-with-me), `drive:<id>` (files in a shared drive), `drive-root:<id>` (the shared drive's own membership) |
| `fileId` | Drive file ID |
| `name` | File name, stored as literal text |
| `mimeType` | Google Docs type or MIME type |
| `link` | Direct link to the file |
| `owner` | Owner address. Empty for shared drive items, which have no owner |
| `sharedDriveId` | Populated when the file lives in a shared drive |
| `trashed` | `yes` if deliberately trashed, `yes (parent)` if swept up in a trashed folder, empty otherwise. Trashed does not mean unshared — see below |
| `finding` | Classification, see below |
| `permType` | `user`, `group`, `domain`, `anyone` |
| `role` | `owner`, `organizer`, `fileOrganizer`, `writer`, `commenter`, `reader` |
| `principal` | Who holds the access |
| `view` | Empty for an ordinary grant. `published` means access to the published rendering rather than the Drive file. `metadata` means folder-metadata visibility only |
| `provenance` | `direct`, `inherited`, or `direct+inherited` |
| `inheritDisabled` | `yes` when only organizers, owners and directly-added principals can reach the item, in which case an inherited row may not be effective — verify before treating it as exposure |
| `aclSource` | `embedded`, `permissions.list`, or an error string |

### Findings

| Finding | Meaning | What to do |
|---|---|---|
| `external-user` | A person outside your domains has access | Review, revoke if unintended |
| `external-group` | An external group has access | Review; you cannot see its members |
| `external-domain` | An entire outside domain has access | Highest persistence — outlives any individual at that organization |
| `anyone-with-link` | Anyone holding the URL can open it | Treat the link as public; it leaks through chat logs and forwarded mail |
| `public-searchable` | Marked as discoverable, so it is eligible to appear in search results for its audience | Fix first |
| `published-view` | Access to the file's published rendering is granted to the reported principal, rather than to the Drive file itself. If `permType` is `anyone`, that rendering is public on the internet | Fix first when `permType` is `anyone` — unpublish in File → Share → Publish to web |
| `published-view-internal` | Published, but reachable only by a principal inside your domains | Informational, not external exposure. Still a broad grant that bypasses per-file sharing |
| `target-audience-review` | Shared with a Workspace target audience, an internal construct that appears as an opaque `*.audience.googledomains.com` domain | Not an external leak; check the audience's membership in Admin console |
| `external-metadata-only` / `semi-trusted-metadata-only` | A limited-access folder is visible in metadata view only. The grantee can see the folder exists but cannot open it or reach its contents | Lower priority than real access, but still information disclosure |
| `externally-owned` | Owned by someone outside your domains | Informational; you cannot remediate it |
| `semi-trusted-user` / `-group` / `-domain` | Access from a domain you listed as semi-trusted | Expected, but visible for review |
| `internal-group-review` | Access via an internal group | Check the group's membership separately for outside members |
| `acl-denied` | Sharing state could not be read | Not evidence the file is unshared — see below |
| `acl-read-failed` | ACL read failed after retries | Re-run the audit |

### Example rows

**A document shared directly with a personal address.** Direct grant on a file you own; remove it in the file's sharing dialog.

```
scope         user
name          Q3 partner budget
finding       external-user
permType      user
role          writer
principal     someone@gmail.com
provenance    direct
aclSource     embedded
```

**A shared drive file exposed through drive membership.** Note `provenance: inherited`, `role: organizer`, and a populated `sharedDriveId`. Nothing was done to this file — the access comes from the drive. Removing it from the file's sharing dialog would achieve nothing; fix the drive's member list. Expect one such row per file in the drive, all pointing at the same underlying grant.

```
scope         drive:0AExampleSharedDriveId
name          Grant reporting 2026
finding       external-user
permType      user
role          organizer
principal     contractor@example.org
provenance    inherited
aclSource     permissions.list
```

**The grant those rows come from.** One row, one place to fix, and it covers every file in the drive. This is why `SHARED_DRIVE_IDS` matters.

```
scope         drive-root:0AExampleSharedDriveId
name          (shared drive root)
finding       external-user
role          organizer
principal     contractor@example.org
provenance    direct
aclSource     permissions.list
```

**Both inherited and direct.** The trap this column exists to catch. Removing the parent grant leaves the direct `writer` in place, and access continues. Both have to go.

```
name          Field contacts 2026
finding       external-user
role          writer
principal     journalist@example.net
provenance    direct+inherited
```

**Indexed by Google.** Not merely link-accessible: `allowFileDiscovery` is set, so it can turn up in search results. Triage these before anything else.

```
name          Security training notes
finding       public-searchable
permType      anyone
role          reader
principal     anyone
provenance    direct
```

**Access through an internal group.** The group is internal, so this is not a leak on its face. But the Drive API will not expand membership, so if `partners@yourdomain.org` contains an outside consultant, that access is real and this row is the only hint you get. Check the group in Admin console or Google Groups.

```
name          Incident timeline
finding       internal-group-review
permType      group
role          commenter
principal     partners@yourdomain.org
provenance    direct
```

**Trashed but still shared.** The owner moved this to Trash and almost certainly considers it gone. The external reader can still open it. Nothing about the permission changed, and nothing will until the file is permanently deleted or the permission is removed. `yes (parent)` in this column instead would mean the file was swept up in a trashed folder rather than deleted deliberately — often a sign that nobody reviewed this particular file at all.

```
name          Old contact list
trashed       yes
finding       external-user
permType      user
role          reader
principal     former-partner@example.org
provenance    direct
```

**Published to the web.** A distinct exposure from link sharing: the grant is to the *published rendering* of the document, and Drive omits these permissions from API responses entirely unless the caller asks for the published view. An audit that does not request it reports nothing here. Remediate through File → Share → Publish to web, not the sharing dialog.

```
name          Annual report draft
finding       published-view
permType      anyone
role          reader
principal     anyone
view          published
provenance    direct
```

**Folder visible in metadata view only.** A limited-access folder where the grantee has read access to the parent. They can see this folder exists; they cannot open it or reach anything inside. Reporting it as `external-user` would overstate the exposure, which is why it gets its own finding — information disclosure, not access.

```
name          Case files 2026
mimeType      application/vnd.google-apps.folder
finding       external-metadata-only
permType      user
role          reader
principal     outsider@example.com
view          metadata
provenance    direct
```

**Unreadable sharing state.** Your account holds this file without sharing rights, typically because it was shared to you by link as a reader. There is an irony worth sitting with: files shared by open link are often the *most* widely exposed files in a Drive, and they are exactly the ones whose ACL you cannot inspect. Only the owner, or a domain-wide audit, can settle them. An `acl-denied` row is never evidence that a file is unshared. A number in the tens out of a thousand files is entirely normal.

```
name          Shared research draft
finding       acl-denied
principal
provenance
aclSource     denied: API call to drive.permissions.list failed with error:
              The user does not have sufficient permissions for this file.
```

### The coverage verdict

The `_info` tab carries one of four verdicts:

| Verdict | Meaning |
|---|---|
| `COMPLETE FOR CONFIGURED SCOPE` | Everything in the configured scope was scanned and every ACL was readable. Note the qualifier: the scope is what you configured, so this says nothing about shared drives you did not list |
| `COMPLETE FOR CONFIGURED SCOPE - N file(s) this account may not inspect` | The scan finished cleanly. N files sit above what an unprivileged account can see. This is the normal result |
| `INCOMPLETE - run paused` | Not finished. Run `continueAudit()` |
| `INCOMPLETE - the audit did not finish cleanly` | Transient API failures survived retries, or Drive returned `incompleteSearch`. Re-run |

The distinction between the second and fourth rows is the point. "The tool failed" and "the tool worked and this is the ceiling of user privilege" are different claims, and a verdict that reported both as failure would be permanently red on any account with shared-with-me files — a warning that is always lit tells you nothing.

### Suggested triage order

1. `public-searchable`, and `published-view` where `permType` is `anyone` — reachable from the open internet
2. `anyone-with-link` — leaks silently through forwarded links
3. `external-domain` — outlives any individual at that organization
4. `drive-root:*` rows — each one grants access to an entire shared drive
5. `external-user` and `external-group` with `provenance: direct` — the file-level grants you can fix directly
6. `internal-group-review` — group memberships to check out of band
7. `target-audience-review` — audience memberships to check in Admin console
8. `external-metadata-only` — folder existence disclosed without content access
9. `acl-denied` — count them, spot-check a few; if any are files you *own*, investigate, because that would be unexpected

Most `external-user` findings in a working organization are legitimate partner sharing. The value of the report is in the ones that surprise you.

---

## Blind spots

These are properties of running as an unprivileged user. No amount of code closes them, and the `_info` tab restates them in every report so they travel with the artifact rather than living in someone's memory.

- **One account.** Files never shared with you are invisible however exposed they are.
- **Group membership.** A grant to an internal group is reported as the group. Outside members hold real access the Drive API will not reveal. Expanding groups needs Admin SDK Directory scopes — a separate privilege decision.
- **Unreadable ACLs.** Files you hold without sharing rights refuse an ACL read.
- **Shared drives you are not a member of.** Invisible.
- **Shared drives you did not list.** Not audited, and the report says so.

---

## Disclaimers

### This script was written with AI assistance

It was produced in an iterative session with a large language model, reviewed against Google's API documentation, and revised across several rounds of adversarial review that found real bugs — including a spreadsheet formula injection and a silent false negative that returned empty results for all shared drive content. Both are fixed. Assume more remain. Read the code.

### Running Apps Script is dangerous

An Apps Script you authorize runs as you, with the scopes you grant, indefinitely, until you revoke it. Pasting a script from the internet into your own Google account is a meaningful security decision and should be treated as one.

Do not blindly copy and paste this or any other script. Read it first. Concretely, check:

- the `oauthScopes` in `appsscript.json` — this is the entire blast radius
- that no code path can make arbitrary outbound HTTP requests: no `UrlFetchApp`. The Drive advanced service talks to Google's API and nowhere else; `UrlFetchApp` is what would let a script talk to anywhere
- that nothing sends mail: no `MailApp`, no `GmailApp`
- that nothing writes to Drive: no `setSharing`, `addEditor`, `removeEditor`, `createFile`, `DriveApp`
- no dynamic code execution: no `eval`, no `new Function`
- no encoded blobs hiding logic: no unexplained `Utilities.base64Decode`
- the OAuth consent screen at authorization time, which is the ground truth about what you actually granted

```bash
grep -nE '(UrlFetchApp|MailApp|GmailApp|DriveApp|CalendarApp)\.|eval\(|new Function|Utilities\.base64|\.(setSharing|addEditor|addViewer|removeEditor|createFile)\(' Code.gs
```

That should return nothing for the files in this repository. The pattern deliberately matches call sites (`DriveApp.`) rather than bare names, because `DriveApp` appears in a comment in `Code.gs` explaining why it is not used — a match on the bare word is a hit you have to read anyway, which is a good habit but a bad automated check.

### Do not blindly hand a script to an AI for review either

Using a language model as a second reviewer is reasonable and it does catch real bugs. It is not a substitute for reading the code, for two reasons.

A script is untrusted input to the reviewer. Comments, string literals and variable names can carry instructions aimed at the model rather than at you — telling it to approve the file, to ignore a particular function, or to describe malicious behaviour as benign. A reviewer that treats source code as instructions rather than as data can be steered into blessing exactly what you asked it to catch. Models also confabulate: some of the review findings in this script's own history were wrong, and one recommended fix would have silently traded away the least-privilege property it had praised in the same document.

Use AI review as one signal among several. Read the code yourself, check claims against primary API documentation rather than the reviewer's summary, and be more suspicious of a confident approval than of a confident objection.

### Scripts can contain invisible characters

Source code can hide content that your eyes and your editor will not show you: zero-width spaces, bidirectional override characters that make code render in a different order than it executes (the Trojan Source class of attack), homoglyphs that make `Drive` and `Drivе` look identical, and non-breaking spaces inside identifiers.

Check before trusting:

```bash
# any non-ASCII character at all
grep -nP '[^\x00-\x7F]' Code.gs

# zero-width, bidi control and byte-order marks specifically.
# The LC_ALL prefix is required: without a UTF-8 locale, grep -P rejects
# code points above 0xFF with "character code point value ... is too large".
LC_ALL=C.UTF-8 grep -nP \
  '[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{FEFF}]' Code.gs

# see every byte, including what your editor renders invisibly
cat -A Code.gs | less
```

Both `grep` commands should produce no output for the files in this repository.

If your `grep` lacks `-P` (BSD grep on macOS, for instance), this needs nothing but Python and catches a wider set — every non-ASCII format, control and space character, named so you can judge it:

```bash
python3 - <<'EOF'
import unicodedata
for path in ('Code.gs', 'appsscript.json'):
    hits = []
    for n, line in enumerate(open(path, encoding='utf-8'), 1):
        for ch in line:
            if ord(ch) > 127 and unicodedata.category(ch) in ('Cf', 'Cc', 'Zs'):
                hits.append((n, hex(ord(ch)), unicodedata.name(ch, 'unnamed')))
    print(path, 'CLEAN' if not hits else hits)
EOF
```

If anything turns up, do not run the script until you understand what it found. Note that a hit is not automatically malicious — a non-breaking space in a comment is untidy, the same character inside an identifier is an attack — which is why these checks report what they found instead of passing or failing.

### General

Run scripts only from sources you trust, and verify them in more than one way. Read them, run mechanical checks over them, check the consent screen, and revoke access when you are finished. No single check is sufficient on its own — that is the whole reason there are several listed above.

This tool produces evidence to reason about, not a verdict to act on unread. Its report states its own limits in the `_info` tab; take those limits seriously rather than reading past them to the findings.

---

## License

MIT. See [LICENSE](LICENSE).

Copyright (c) 2026 RESIDENT.NGO

MIT asks one thing of you: keep the copyright notice and the license text with the code. That single line is doing real work for a tool like this one. This README's central safety message is that you should run scripts only from sources you trust and verify them in more than one way — and a fork circulating with no trace of where it came from, and no warranty disclaimer attached, undercuts exactly that. Attribution will not stop anyone adding an exfiltration call to a copy of this script, but it keeps the honest chain of custody legible, which for this audience is a security property rather than a courtesy.
