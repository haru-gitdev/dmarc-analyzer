const DMARC_CONFIG = {
  folderProperty: 'DMARC_REPORT_FOLDER_ID',
  notificationEmailProperty: 'DMARC_NOTIFICATION_EMAIL',
  processedLabel: 'processed_dmarc_report',
  searchQuery: 'in:inbox (集約レポート OR dmarc) has:attachment -label:processed_dmarc_report',
  maxFilesPerRun: 20,
  sheets: {
    summary: 'Summary',
    issues: 'Issues',
    failures: 'Failures',
    raw: 'Raw',
    errors: 'Errors',
    files: 'Files'
  }
};

const DMARC_RECORD_HEADERS = [
  'Run ID', 'Processed At', 'Source File ID', 'Report File', 'Report Org',
  'Report ID', 'Begin', 'End', 'Source IP', 'Count', 'Header From',
  'Envelope From', 'SPF Domain', 'SPF Result', 'DKIM Domain',
  'DKIM Result', 'DKIM Selector', 'DMARC Result', 'Disposition', 'Evaluation'
];

const DMARC_ISSUE_HEADERS = DMARC_RECORD_HEADERS.concat(['Issue']);

/**
 * 既存トリガーとの互換入口。保存・解析・Sheet記録・通知を一括実行する。
 */
function saveDmarcAttachmentsAndArchive() {
  return runDmarcPipeline();
}

function runDmarcPipeline() {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(5000)) {
    console.log('Another DMARC pipeline run is active; skipping.');
    return;
  }

  try {
    const folderId = PropertiesService.getScriptProperties()
      .getProperty(DMARC_CONFIG.folderProperty);
    if (!folderId) {
      throw new Error('Script property DMARC_REPORT_FOLDER_ID is not set.');
    }

    const rootFolder = DriveApp.getFolderById(folderId);
    const incomingFolder = getOrCreateFolder_(rootFolder, 'incoming');
    const processedFolder = getOrCreateFolder_(rootFolder, 'processed');
    const sheets = prepareSheets_();

    const savedCount = saveDmarcAttachments_(incomingFolder);
    const result = analyzePendingReports_(rootFolder, incomingFolder, processedFolder, sheets);
    console.log(JSON.stringify({ savedCount: savedCount, analysis: result }));

    if (result.processedFiles > 0) {
      notifyResult_(result, sheets.issues);
    }
    return result;
  } catch (error) {
    recordPipelineError_(error);
    throw error;
  } finally {
    lock.releaseLock();
  }
}

function saveDmarcAttachments_(incomingFolder) {
  const threads = GmailApp.search(DMARC_CONFIG.searchQuery);
  let processedLabel = GmailApp.getUserLabelByName(DMARC_CONFIG.processedLabel);
  if (!processedLabel) {
    processedLabel = GmailApp.createLabel(DMARC_CONFIG.processedLabel);
  }

  let savedCount = 0;
  threads.forEach(function(thread) {
    let threadSaved = 0;
    const messages = thread.getMessages();
    messages.forEach(function(message) {
      message.getAttachments().forEach(function(attachment) {
        const name = attachment.getName();
        const lowerName = name.toLowerCase();
        if (!lowerName.endsWith('.zip') && !lowerName.endsWith('.gz')) {
          console.log('Skipping non-ZIP/GZ attachment: ' + name);
          return;
        }
        const file = incomingFolder.createFile(attachment.copyBlob());
        file.setName(name);
        file.setDescription('DMARC attachment from Gmail message ' + message.getId());
        threadSaved += 1;
        savedCount += 1;
        console.log('Saved attachment: ' + name);
      });
    });

    if (threadSaved > 0) {
      thread.moveToArchive();
      thread.addLabel(processedLabel);
      thread.markRead();
    }
  });
  return savedCount;
}

function analyzePendingReports_(rootFolder, incomingFolder, processedFolder, sheets) {
  const runId = Utilities.getUuid();
  const processedAt = new Date();
  const states = loadLatestFileStates_(sheets.files);
  const candidates = collectCandidateFiles_(rootFolder, incomingFolder)
    .slice(0, DMARC_CONFIG.maxFilesPerRun);

  let processedFiles = 0;
  let reportFiles = [];
  let allRecords = [];

  candidates.forEach(function(file) {
    const fileId = file.getId();
    const previousState = states[fileId];
    try {
      if (previousState === 'SUCCESS') {
        return;
      }
      if (previousState === 'ANALYZED') {
        moveToProcessed_(file, processedFolder);
        appendRows_(sheets.files, [[fileId, file.getName(), new Date(), 'SUCCESS', 'Recovered pending move']]);
        return;
      }

      const records = parseArchiveFile_(file);
      if (!records.length) {
        throw new Error('No DMARC records found in the archive.');
      }

      const rows = records.map(function(record) {
        return recordToRow_(runId, processedAt, file, record);
      });
      const failureRows = rows.filter(function(row) {
        return row[17] !== 'pass';
      });
      const issueRows = records.map(function(record, index) {
        const reasons = issueReasons_(record);
        return reasons.length ? rows[index].concat([reasons.join(' / ')]) : null;
      }).filter(function(row) { return row !== null; });

      appendRows_(sheets.raw, rows);
      appendRows_(sheets.failures, failureRows);
      appendRows_(sheets.issues, issueRows);
      appendRows_(sheets.files, [[fileId, file.getName(), new Date(), 'ANALYZED', 'Sheet rows committed']]);
      moveToProcessed_(file, processedFolder);
      appendRows_(sheets.files, [[fileId, file.getName(), new Date(), 'SUCCESS', 'Moved to processed']]);

      processedFiles += 1;
      reportFiles.push(file.getName());
      allRecords = allRecords.concat(records);
    } catch (error) {
      appendRows_(sheets.files, [[fileId, file.getName(), new Date(), 'ERROR', String(error)]]);
      appendRows_(sheets.errors, [[new Date(), fileId, file.getName(), 'analyze', String(error)]]);
      console.error('Failed to process ' + file.getName() + ': ' + error);
    }
  });

  const summary = summarizeRecords_(allRecords);
  if (processedFiles > 0) {
    const issuesUrl = getSheetUrl_(sheets.issues);
    appendRows_(sheets.summary, [[
      runId, processedAt, processedFiles, reportFiles.join('\n'), summary.recordRows,
      summary.messageCount, summary.spfFailures, summary.dkimFailures,
      summary.dmarcFailures, issuesUrl
    ]]);
  }

  formatResultSheets_(sheets);
  return {
    runId: runId,
    processedFiles: processedFiles,
    reportFiles: reportFiles,
    recordRows: summary.recordRows,
    messageCount: summary.messageCount,
    spfFailures: summary.spfFailures,
    dkimFailures: summary.dkimFailures,
    dmarcFailures: summary.dmarcFailures,
    issueRows: summary.issueRows,
    spfResults: summary.spfResults,
    dkimResults: summary.dkimResults,
    dmarcResults: summary.dmarcResults,
    issuesUrl: getSheetUrl_(sheets.issues)
  };
}

function collectCandidateFiles_(rootFolder, incomingFolder) {
  const found = {};
  [incomingFolder, rootFolder].forEach(function(folder) {
    const files = folder.getFiles();
    while (files.hasNext()) {
      const file = files.next();
      const lowerName = file.getName().toLowerCase();
      if (lowerName.endsWith('.zip') || lowerName.endsWith('.gz') || lowerName.endsWith('.xml')) {
        found[file.getId()] = file;
      }
    }
  });
  return Object.keys(found).map(function(id) { return found[id]; });
}

function parseArchiveFile_(file) {
  const name = file.getName();
  const lowerName = name.toLowerCase();
  let xmlItems = [];

  if (lowerName.endsWith('.zip')) {
    xmlItems = Utilities.unzip(file.getBlob())
      .filter(function(blob) { return blob.getName().toLowerCase().endsWith('.xml'); })
      .map(function(blob) { return { name: blob.getName(), text: blob.getDataAsString('UTF-8') }; });
  } else if (lowerName.endsWith('.gz')) {
    const xmlBlob = Utilities.ungzip(file.getBlob());
    xmlItems = [{ name: name.replace(/\.gz$/i, ''), text: xmlBlob.getDataAsString('UTF-8') }];
  } else if (lowerName.endsWith('.xml')) {
    xmlItems = [{ name: name, text: file.getBlob().getDataAsString('UTF-8') }];
  }

  let records = [];
  xmlItems.forEach(function(item) {
    records = records.concat(parseDmarcXml_(item.text, item.name));
  });
  return records;
}

function parseDmarcXml_(xmlText, xmlName) {
  const root = XmlService.parse(xmlText).getRootElement();
  const metadata = child_(root, 'report_metadata');
  const dateRange = metadata ? child_(metadata, 'date_range') : null;
  const policy = child_(root, 'policy_published');
  const policyData = {
    domain: childText_(policy, 'domain'),
    adkim: childText_(policy, 'adkim') || 'r',
    aspf: childText_(policy, 'aspf') || 'r'
  };
  const reportData = {
    xmlName: xmlName,
    orgName: childText_(metadata, 'org_name'),
    reportId: childText_(metadata, 'report_id'),
    begin: epochDate_(childText_(dateRange, 'begin')),
    end: epochDate_(childText_(dateRange, 'end'))
  };

  return children_(root, 'record').map(function(recordElement) {
    return parseRecord_(recordElement, policyData, reportData);
  });
}

function parseRecord_(recordElement, policy, report) {
  const row = child_(recordElement, 'row');
  const evaluated = child_(row, 'policy_evaluated');
  const identifiers = child_(recordElement, 'identifiers');
  const authResults = child_(recordElement, 'auth_results');
  const spfResults = authResults ? children_(authResults, 'spf').map(function(spf) {
    return { domain: childText_(spf, 'domain'), result: childText_(spf, 'result') };
  }) : [];
  const dkimResults = authResults ? children_(authResults, 'dkim').map(function(dkim) {
    return {
      domain: childText_(dkim, 'domain'),
      result: childText_(dkim, 'result'),
      selector: childText_(dkim, 'selector')
    };
  }) : [];
  const spf = spfResults.length ? spfResults[0] : { domain: '', result: '' };
  const dkim = dkimResults.filter(function(value) { return value.result === 'pass'; })[0] ||
    dkimResults[0] || { domain: '', result: '', selector: '' };
  const headerFrom = childText_(identifiers, 'header_from');
  const evaluatedSpf = childText_(evaluated, 'spf');
  const evaluatedDkim = childText_(evaluated, 'dkim');
  let dmarcResult;
  let evaluation;

  if (evaluatedSpf && evaluatedDkim) {
    dmarcResult = evaluatedSpf === 'pass' || evaluatedDkim === 'pass' ? 'pass' : 'fail';
    evaluation = 'policy_evaluated';
  } else {
    const spfAligned = spf.result === 'pass' && aligned_(spf.domain, headerFrom, policy.aspf);
    const dkimAligned = dkim.result === 'pass' && aligned_(dkim.domain, headerFrom, policy.adkim);
    dmarcResult = spfAligned || dkimAligned ? 'pass' : 'fail';
    evaluation = 'manual_evaluation';
  }

  return {
    report: report,
    sourceIp: childText_(row, 'source_ip'),
    count: Number(childText_(row, 'count') || 1),
    headerFrom: headerFrom,
    envelopeFrom: childText_(identifiers, 'envelope_from'),
    spfDomain: spf.domain,
    spfResult: spf.result,
    dkimDomain: dkim.domain,
    dkimResult: dkim.result,
    dkimSelector: dkim.selector,
    dmarcResult: dmarcResult,
    disposition: childText_(evaluated, 'disposition'),
    evaluation: evaluation
  };
}

function recordToRow_(runId, processedAt, file, record) {
  return [
    runId, processedAt, file.getId(), file.getName(), record.report.orgName,
    record.report.reportId, record.report.begin, record.report.end,
    record.sourceIp, record.count, record.headerFrom, record.envelopeFrom,
    record.spfDomain, record.spfResult, record.dkimDomain, record.dkimResult,
    record.dkimSelector, record.dmarcResult, record.disposition, record.evaluation
  ];
}

function summarizeRecords_(records) {
  return {
    recordRows: records.length,
    messageCount: records.reduce(function(total, record) { return total + record.count; }, 0),
    spfFailures: records.filter(function(record) { return record.spfResult !== 'pass'; }).length,
    dkimFailures: records.filter(function(record) { return record.dkimResult !== 'pass'; }).length,
    dmarcFailures: records.filter(function(record) { return record.dmarcResult !== 'pass'; }).length,
    issueRows: records.filter(function(record) { return issueReasons_(record).length > 0; }).length,
    spfResults: countResults_(records, 'spfResult'),
    dkimResults: countResults_(records, 'dkimResult'),
    dmarcResults: countResults_(records, 'dmarcResult')
  };
}

function issueReasons_(record) {
  const reasons = [];
  [['SPF', record.spfResult], ['DKIM', record.dkimResult], ['DMARC', record.dmarcResult]]
    .forEach(function(item) {
      const result = normalizeResult_(item[1]);
      if (result !== 'pass') {
        reasons.push(item[0] + ': ' + result);
      }
    });
  return reasons;
}

function normalizeResult_(result) {
  return String(result || 'none').toLowerCase();
}

function countResults_(records, key) {
  const counts = { pass: 0, softfail: 0, fail: 0, other: 0 };
  records.forEach(function(record) {
    const result = normalizeResult_(record[key]);
    if (Object.prototype.hasOwnProperty.call(counts, result)) {
      counts[result] += 1;
    } else {
      counts.other += 1;
    }
  });
  return counts;
}

function prepareSheets_() {
  const spreadsheet = SpreadsheetApp.getActiveSpreadsheet();
  const sheets = {
    summary: ensureSheet_(spreadsheet, DMARC_CONFIG.sheets.summary, [
      'Run ID', 'Processed At', 'Report Files', 'File Names', 'Record Rows',
      'Message Count', 'SPF Failures', 'DKIM Failures', 'DMARC Failures', 'Issues Link'
    ], [[
      'Run ID', 'Processed At', 'Report Files', 'File Names', 'Record Rows',
      'Message Count', 'SPF Failures', 'DKIM Failures', 'DMARC Failures', 'Failures Link'
    ]]),
    issues: ensureSheet_(spreadsheet, DMARC_CONFIG.sheets.issues, DMARC_ISSUE_HEADERS),
    failures: ensureSheet_(spreadsheet, DMARC_CONFIG.sheets.failures, DMARC_RECORD_HEADERS),
    raw: ensureSheet_(spreadsheet, DMARC_CONFIG.sheets.raw, DMARC_RECORD_HEADERS),
    errors: ensureSheet_(spreadsheet, DMARC_CONFIG.sheets.errors, [
      'Occurred At', 'Source File ID', 'Report File', 'Stage', 'Error'
    ]),
    files: ensureSheet_(spreadsheet, DMARC_CONFIG.sheets.files, [
      'Source File ID', 'Report File', 'Updated At', 'Status', 'Note'
    ])
  };
  sheets.files.hideSheet();
  return sheets;
}

function ensureSheet_(spreadsheet, name, headers, legacyHeaders) {
  let sheet = spreadsheet.getSheetByName(name);
  if (!sheet && name === DMARC_CONFIG.sheets.summary) {
    const defaultSheet = spreadsheet.getSheetByName('シート1');
    if (defaultSheet && defaultSheet.getLastRow() === 0 && defaultSheet.getLastColumn() === 0) {
      defaultSheet.setName(name);
      sheet = defaultSheet;
    }
  }
  if (!sheet) {
    sheet = spreadsheet.insertSheet(name);
  }
  if (sheet.getLastRow() === 0) {
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
  } else {
    const currentHeaders = sheet.getRange(1, 1, 1, headers.length).getValues()[0];
    const currentKey = currentHeaders.join('\u0000');
    const expectedKey = headers.join('\u0000');
    const isLegacy = (legacyHeaders || []).some(function(legacy) {
      return legacy.join('\u0000') === currentKey;
    });
    if (isLegacy) {
      sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
    } else if (currentKey !== expectedKey) {
      throw new Error('Unexpected headers in sheet: ' + name);
    }
  }
  sheet.setFrozenRows(1);
  sheet.getRange(1, 1, 1, headers.length)
    .setFontWeight('bold')
    .setBackground('#d9eaf7');
  return sheet;
}

function formatResultSheets_(sheets) {
  [sheets.summary, sheets.issues, sheets.failures, sheets.raw, sheets.errors].forEach(function(sheet) {
    const lastColumn = sheet.getLastColumn();
    if (lastColumn > 0) {
      sheet.autoResizeColumns(1, lastColumn);
      for (let column = 1; column <= lastColumn; column += 1) {
        if (sheet.getColumnWidth(column) > 320) {
          sheet.setColumnWidth(column, 320);
        }
      }
    }
  });

  [sheets.issues, sheets.failures, sheets.raw].forEach(function(sheet) {
    const lastRow = sheet.getLastRow();
    if (lastRow > 1) {
      const resultColumns = [14, 16, 18];
      resultColumns.forEach(function(column) {
        sheet.getRange(2, column, lastRow - 1, 1).setFontWeight('bold');
      });
      const ranges = resultColumns.map(function(column) {
        return sheet.getRange(2, column, Math.max(1, sheet.getMaxRows() - 1), 1);
      });
      const rules = [
        resultRule_('pass', '#d9f2e3', '#067647', ranges),
        resultRule_('softfail', '#fff3cd', '#8a5700', ranges),
        resultRule_('fail', '#f9d6d2', '#b42318', ranges)
      ];
      sheet.setConditionalFormatRules(rules);
    }
  });
}

function resultRule_(value, background, color, ranges) {
  return SpreadsheetApp.newConditionalFormatRule()
    .whenTextEqualTo(value).setBackground(background).setFontColor(color)
    .setRanges(ranges).build();
}

function loadLatestFileStates_(sheet) {
  const states = {};
  if (sheet.getLastRow() < 2) {
    return states;
  }
  sheet.getRange(2, 1, sheet.getLastRow() - 1, 4).getValues().forEach(function(row) {
    states[String(row[0])] = String(row[3]);
  });
  return states;
}

function moveToProcessed_(file, processedFolder) {
  const monthFolder = getOrCreateFolder_(
    processedFolder,
    Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'yyyy-MM')
  );
  file.moveTo(monthFolder);
}

function getOrCreateFolder_(parent, name) {
  const folders = parent.getFoldersByName(name);
  return folders.hasNext() ? folders.next() : parent.createFolder(name);
}

function appendRows_(sheet, rows) {
  if (!rows.length) {
    return;
  }
  sheet.getRange(sheet.getLastRow() + 1, 1, rows.length, rows[0].length).setValues(rows);
}

function getSheetUrl_(sheet) {
  return SpreadsheetApp.getActiveSpreadsheet().getUrl() + '#gid=' + sheet.getSheetId();
}

function notifyResult_(result, issuesSheet) {
  const scriptProperties = PropertiesService.getScriptProperties();
  const recipient = scriptProperties.getProperty(DMARC_CONFIG.notificationEmailProperty) ||
    Session.getEffectiveUser().getEmail();
  if (!recipient) {
    console.log('Notification skipped: recipient email is unavailable.');
    return;
  }

  const dmarcStatus = aggregateResult_(result.dmarcResults);
  const spfStatus = aggregateResult_(result.spfResults);
  const dkimStatus = aggregateResult_(result.dkimResults);
  const subject = '[DMARC ' + dmarcStatus + '] SPF:' + spfStatus +
    ' DKIM:' + dkimStatus + ' (' + result.messageCount + '通)';
  const issuesUrl = getSheetUrl_(issuesSheet);
  const body = [
    '総合判定: DMARC ' + dmarcStatus,
    '',
    '対象レポート: ' + result.processedFiles + '件',
    'メール数: ' + result.messageCount + '件',
    resultLine_('DMARC', result.dmarcResults),
    resultLine_('SPF', result.spfResults),
    resultLine_('DKIM', result.dkimResults),
    '',
    'Issues: ' + result.issueRows + '件',
    '問題箇所の詳細:',
    issuesUrl
  ].join('\n');
  const htmlBody = '<div style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;color:#172033">' +
    '<h2 style="margin:0 0 16px">総合判定: ' + resultBadge_(dmarcStatus) + '</h2>' +
    '<p>対象レポート: ' + result.processedFiles + '件<br>メール数: ' + result.messageCount + '件</p>' +
    '<table style="border-collapse:collapse;margin:16px 0">' +
    resultHtmlRow_('DMARC', result.dmarcResults) +
    resultHtmlRow_('SPF', result.spfResults) +
    resultHtmlRow_('DKIM', result.dkimResults) +
    '</table><p>Issues: <strong>' + result.issueRows + '件</strong></p>' +
    '<p><a href="' + escapeHtml_(issuesUrl) + '" style="display:inline-block;padding:10px 14px;' +
    'background:#175cd3;color:#fff;text-decoration:none;border-radius:6px">問題箇所を確認</a></p></div>';
  MailApp.sendEmail({ to: recipient, subject: subject, body: body, htmlBody: htmlBody });
}

function aggregateResult_(counts) {
  if (counts.fail > 0) return 'FAIL';
  if (counts.softfail > 0) return 'SOFTFAIL';
  if (counts.other > 0) return 'OTHER';
  return 'PASS';
}

function resultLine_(name, counts) {
  return name + ': PASS ' + counts.pass + ' / SOFTFAIL ' + counts.softfail +
    ' / FAIL ' + counts.fail + ' / OTHER ' + counts.other;
}

function resultHtmlRow_(name, counts) {
  return '<tr><th style="padding:8px 12px;text-align:left;border-bottom:1px solid #ddd">' + name +
    '</th><td style="padding:8px 12px;border-bottom:1px solid #ddd">' +
    resultBadge_('PASS') + ' ' + counts.pass + '&nbsp;&nbsp;' +
    resultBadge_('SOFTFAIL') + ' ' + counts.softfail + '&nbsp;&nbsp;' +
    resultBadge_('FAIL') + ' ' + counts.fail + '&nbsp;&nbsp;' +
    'OTHER ' + counts.other + '</td></tr>';
}

function resultBadge_(status) {
  const palette = {
    PASS: ['#d9f2e3', '#067647'],
    SOFTFAIL: ['#fff3cd', '#8a5700'],
    FAIL: ['#f9d6d2', '#b42318'],
    OTHER: ['#eaecf0', '#344054']
  };
  const colors = palette[status] || palette.OTHER;
  return '<span style="display:inline-block;padding:3px 8px;border-radius:999px;' +
    'background:' + colors[0] + ';color:' + colors[1] + ';font-weight:700">' + status + '</span>';
}

function escapeHtml_(value) {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function recordPipelineError_(error) {
  try {
    const spreadsheet = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ensureSheet_(spreadsheet, DMARC_CONFIG.sheets.errors, [
      'Occurred At', 'Source File ID', 'Report File', 'Stage', 'Error'
    ]);
    appendRows_(sheet, [[new Date(), '', '', 'pipeline', String(error)]]);
  } catch (loggingError) {
    console.error('Unable to record pipeline error: ' + loggingError);
  }
}

function child_(element, name) {
  if (!element) {
    return null;
  }
  const children = element.getChildren();
  for (let index = 0; index < children.length; index += 1) {
    if (children[index].getName() === name) {
      return children[index];
    }
  }
  return null;
}

function children_(element, name) {
  if (!element) {
    return [];
  }
  return element.getChildren().filter(function(value) { return value.getName() === name; });
}

function childText_(element, name) {
  const value = child_(element, name);
  return value ? value.getText() : '';
}

function epochDate_(value) {
  return value ? new Date(Number(value) * 1000) : '';
}

function aligned_(domainA, domainB, mode) {
  if (!domainA || !domainB) {
    return false;
  }
  const left = domainA.toLowerCase();
  const right = domainB.toLowerCase();
  if (left === right) {
    return true;
  }
  if (mode !== 'r') {
    return false;
  }
  return organizationalDomain_(left) === organizationalDomain_(right);
}

function organizationalDomain_(domain) {
  const parts = domain.split('.');
  return parts.length > 1 ? parts.slice(-2).join('.') : domain;
}

/**
 * 外部データやDriveへ書き込まず、XML解析ロジックだけを検証する。
 */
function selfTestDmarcPipeline() {
  const sample = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<feedback><report_metadata><org_name>Test</org_name><report_id>self-test</report_id>' +
    '<date_range><begin>1700000000</begin><end>1700086400</end></date_range></report_metadata>' +
    '<policy_published><domain>example.com</domain><adkim>r</adkim><aspf>r</aspf><p>reject</p></policy_published>' +
    '<record><row><source_ip>192.0.2.1</source_ip><count>3</count>' +
    '<policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>' +
    '</row><identifiers><header_from>example.com</header_from><envelope_from>bounce.example.net</envelope_from></identifiers>' +
    '<auth_results><spf><domain>example.net</domain><result>fail</result></spf>' +
    '<dkim><domain>example.net</domain><selector>s1</selector><result>fail</result></dkim></auth_results>' +
    '</record></feedback>';
  const records = parseDmarcXml_(sample, 'self-test.xml');
  const summary = summarizeRecords_(records);
  const reasons = issueReasons_(records[0]);
  if (records.length !== 1 || records[0].dmarcResult !== 'fail' || records[0].count !== 3 ||
      summary.spfResults.fail !== 1 || summary.dkimResults.fail !== 1 ||
      summary.dmarcResults.fail !== 1 || reasons.join(' / ') !== 'SPF: fail / DKIM: fail / DMARC: fail') {
    throw new Error('DMARC self-test failed: ' + JSON.stringify(records));
  }
  console.log('DMARC self-test passed: ' + JSON.stringify(summary));
  return true;
}
