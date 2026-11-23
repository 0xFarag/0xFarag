// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {routeLinks} = require('./homepage-paths.cjs');

module.exports = async function verifyWorkbench(page, origin, width) {
  await page.goto(origin);
  if (width < 500) {
    await page.locator('.mobile-nav summary').click();
    await routeLinks(page.locator('.mobile-nav nav'), '/workbench/').click();
  } else {
    assert(await routeLinks(page.locator('.wide-nav'), '/workbench/').isVisible());
    await routeLinks(page.locator('#werkzeuge'), '/workbench/').first().click();
  }
  await page.locator('#add-file:enabled').waitFor();
  assert(await page.locator('#document').isHidden(), 'Start without a sample or inferred customer case');
  await page.locator('#new-source summary').click();
  await page.locator('#new-title').fill('Sensitive system name');
  await page.locator('#new-summary').fill('Private observation');
  await page.locator('#new-case-form button[type=submit]').click();
  await page.locator('#document').waitFor();
  assert.equal(await page.locator('#case-title').innerText(), 'Sensitive system name');
  await page.locator('#ticket-tools summary').click();
  await page.locator('#ticket-subject').fill('Review access policy');
  await page.locator('#ticket-owner').fill('Platform team');
  await page.locator('#ticket-due').fill('2027-01-20');
  await page.locator('#ticket-remediation').fill('Remove the surplus grant.');
  await page.locator('#ticket-acceptance').fill('Restore the expected policy.');
  await page.locator('#export-language').selectOption('fr');
  await page.locator('#ticket-format').selectOption('jira');
  const [ticket] = await Promise.all([page.waitForEvent('download'), page.locator('#download-ticket').click()]);
  const ticketText = await fs.readFile(await ticket.path(),'utf8');
  assert.match(ticket.suggestedFilename(), /-fr\.txt$/);
  assert.match(ticketText, /Review access policy/);
  assert.match(ticketText, /Platform team/);
  assert.match(ticketText, /2027-01-20/);
  assert.match(ticketText, /Remove the surplus grant/);
  assert.match(ticketText, /Restore the expected policy/);
  assert(!ticketText.includes('Sensitive system') && !ticketText.includes('Private observation'));
  await page.locator('#report-tools summary').click();
  await page.locator('#export-language').selectOption('ar');
  const [clientReport] = await Promise.all([page.waitForEvent('download'), page.locator('#download-report').click()]);
  const html = await fs.readFile(await clientReport.path(),'utf8');
  assert.match(html, /lang="ar"/);
  assert.match(html, /dir="rtl"/);
  assert(!html.includes('Sensitive system') && !html.includes('Private observation') && !html.includes('Platform team'));
  const manual = await page.locator('#source').inputValue();
  const [manualSource] = await Promise.all([page.waitForEvent('download'), page.locator('#save-manual').click()]);
  const archived = JSON.parse(await fs.readFile(await manualSource.path(),'utf8'));
  assert.equal(archived.title, 'Sensitive system name');
  const languageMenu = page.locator('#az-language');
  if (await languageMenu.count()) {
    for (const lang of ['en', 'it', 'de']) {
      await languageMenu.locator('summary').click();
      await languageMenu.locator('[data-az-lang="' + lang + '"]').click();
      assert.equal(await page.locator('#case-title').innerText(), 'Sensitive system name');
      assert.equal(await page.locator('#ticket-owner').inputValue(), 'Platform team');
      assert.equal(await page.locator('#source').inputValue(), manual);
      assert.equal(await page.locator('#export-language').inputValue(), 'ar');
    }
  }
  await page.locator('#source').selectOption('demo-c');
  await page.waitForFunction(() => document.querySelectorAll('#cases li').length === 2);
  await page.locator('#source').selectOption(manual);
  await page.waitForFunction(() => document.querySelector('#case-title').textContent === 'Sensitive system name');
  assert.equal(await page.locator('#ticket-owner').inputValue(), 'Platform team');
  await page.locator('#export-language').selectOption('de');
  await page.locator('#report-tools summary').click();
  await page.locator('#ticket-tools summary').click();
  await page.locator('#source').selectOption('demo-c');
  await page.waitForFunction(() => document.querySelectorAll('#cases li').length === 2);
  assert.deepEqual(await page.locator('#metrics dd').allTextContents(), ['2', '1', '1', '1']);
  await page.locator('#filter').selectOption('not_retested');
  assert.equal(await page.locator('#cases li').count(), 1);
  await page.locator('#tab-decision').focus();
  await page.keyboard.press('End');
  await page.locator('#note').fill('Private review information');
  await page.locator('#disposition').selectOption('follow_up');
  const [download] = await Promise.all([page.waitForEvent('download'), page.locator('#download').click()]);
  const report = await fs.readFile(await download.path(), 'utf8');
  const result = JSON.parse(report);
  assert.equal(result.signed, false);
  assert.deepEqual(result.cases.map(row => row.evidence_status), ['fix_verified', 'not_retested']);
  assert.equal(result.cases[1].review_state, 'follow_up');
  assert(!report.includes('Private review information'));
  await page.locator('#source').selectOption('demo-b');
  await page.waitForFunction(() => document.getElementById('identity').textContent.startsWith('Demo B'));
  await page.locator('#source').selectOption('demo-index');
  await page.waitForFunction(() => document.querySelectorAll('#cases li').length === 6);
  await page.locator('#source').selectOption('demo-blue');
  await page.waitForFunction(() => document.querySelectorAll('#cases li').length === 4);
  assert.deepEqual(await page.locator('#metrics dd').allTextContents(), ['4', '1', '1']);
  await page.locator('#filter').selectOption('soc_observed');
  await page.locator('#tab-decision').click();
  assert.match(await page.locator('#window-coverage').innerText(), /1 von 2/);
  await page.locator('#snapshot-comparison summary').first().click();
  await page.getByRole('button', {name: 'Beispielvergleich öffnen'}).click();
  await page.getByText('Fall geändert', {exact: true}).first().waitFor();

  const requests = [];
  const recordRequest = request => requests.push(request.url());
  page.on('request', recordRequest);
  try {
    const bytes = await fs.readFile(path.join(__dirname, '../public/proof/mixed-c-result.json'));
    await page.locator('#files').setInputFiles({
      name: 'local.json', mimeType: 'application/json', buffer: Buffer.concat([bytes, Buffer.from('\n')])
    });
    await page.getByText('Lokale Belegdatei', {exact: true}).waitFor();
    assert.deepEqual(requests, [], 'Opening a local case sent a network request');
  } finally {
    page.off('request', recordRequest);
  }
};
