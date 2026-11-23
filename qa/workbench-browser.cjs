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
  await page.locator('#document').waitFor();
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
