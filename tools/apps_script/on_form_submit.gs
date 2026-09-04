/**
 * Report intake: on every form submission, send the row to the list repository as a repository_dispatch
 * event so the case workflow builds the case (.github/workflows/case.yml). Bound to the responses sheet
 * of "Report to Verdetto"; trigger: From spreadsheet, On form submit.
 *
 * Setup (once, by the operator):
 *   1. Extensions > Apps Script in the responses sheet; paste this file; save.
 *   2. Project Settings > Script Properties: GITHUB_TOKEN = a fine-grained token limited to
 *      verdettoqr/link-safety-list with "Contents: read and write" (repository_dispatch needs it).
 *   3. Triggers > Add trigger: onFormSubmit, event source "From spreadsheet", event type "On form submit".
 *      Authorize when asked (the script reads this sheet and calls api.github.com; nothing else).
 * The reporter's email, if given, never leaves the sheet: the payload carries only whether one was given.
 */
var REPO = 'verdettoqr/link-safety-list';
var KINDS = {
  'A link, Wi-Fi network, payment address, or phone number that looks like a scam': 's',
  'The app read a code wrong, or could not read it': 'r',
  'Product, book, medicine, or other details were wrong': 'd',
  'Something else: a mistake in the app, a translation, a suggestion': 'o',
  'My site or link is listed by mistake': 'm'
};

function onFormSubmit(e) {
  var v = e.namedValues || {};
  var first = function (k) { return (v[k] && v[k][0]) ? String(v[k][0]).trim() : ''; };
  var kindText = first('What are you reporting?');
  var payload = {
    kind: KINDS[kindText] || 'o',
    content: first('What was scanned? The exact text the app showed (remove anything private)').slice(0, 2000),
    found: first('Where did you find the code? (for example: a sticker on a parking meter, a menu, an email)').slice(0, 300),
    warnings: first('Warnings the app showed (prefilled if you came from the app)').slice(0, 300),
    versions: first('App, list, version, and phone (prefilled if you came from the app)').slice(0, 200)
        || first('App version, list version, and phone (prefilled if you came from the app)').slice(0, 200),
    report_id: String(e.range ? e.range.getRow() : Date.now()),
    reported_at: new Date().toISOString(),
    email_given: first('Your email, only if you want a reply (optional; used for nothing else)') ? 'true' : 'false'
  };
  if (!payload.content && payload.kind !== 'o') {
    // nothing to check; the description alone is handled from the sheet by the digest
  }
  var token = PropertiesService.getScriptProperties().getProperty('GITHUB_TOKEN');
  if (!token) { throw new Error('GITHUB_TOKEN is not set in Script Properties'); }
  var res = UrlFetchApp.fetch('https://api.github.com/repos/' + REPO + '/dispatches', {
    method: 'post',
    contentType: 'application/json',
    headers: { Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
    payload: JSON.stringify({ event_type: 'report', client_payload: payload }),
    muteHttpExceptions: true
  });
  if (res.getResponseCode() >= 300) {
    throw new Error('dispatch failed: ' + res.getResponseCode() + ' ' + res.getContentText().slice(0, 200));
  }
}
