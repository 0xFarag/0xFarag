// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';

const assert = require('node:assert/strict');
const cockpitFixture = require('./fixtures/team-proof-cockpit.json');
const indexedFixture = require('./fixtures/team-index-cockpit.json');

async function verifySignedCockpit(page, hero) {
  const file = (name, value) => ({name, mimeType:'application/json', buffer:Buffer.from(JSON.stringify(value))});
  await page.locator('#proof-package').setInputFiles(file('package.json',cockpitFixture.proof.handover));
  await page.locator('#proof-key').setInputFiles(file('trust.json',cockpitFixture.trustedKey));
  await hero.locator('#beweis-cockpit button').click();
  await page.locator('#proof-result:visible').waitFor();
  assert.equal(await page.locator('#proof-rows option').count(),2);
  assert.match(await page.locator('#proof-counts').innerText(),/Nicht nachgeprüft/);
  assert.match(await page.locator('#proof-case').innerText(),/keinen signierten Belegindex/);
  await page.locator('#proof-original').setInputFiles({name:'original.har',mimeType:'application/json',buffer:Buffer.from(cockpitFixture.original)});
  await page.locator('#proof-match').filter({hasText:'entspricht einer signierten Quelle'}).waitFor();
  await page.locator('#proof-clear').click();
  assert(await page.locator('#proof-result').isHidden());
  await page.locator('#proof-package').setInputFiles(file('indexed.json',indexedFixture.package));
  await page.locator('#proof-key').setInputFiles(file('trust.json',indexedFixture.trustedKey));
  await hero.locator('#beweis-cockpit button').click();
  await page.locator('#proof-result:visible').waitFor();
  const rows = indexedFixture.package.report.appendix;
  const reviewed = rows.findIndex(row => row.evidence_index.experiments.length);
  await page.locator('#proof-rows').selectOption(String(reviewed));
  const entry = page.locator('#proof-case');
  await entry.getByRole('heading',{name:'Signierter Belegindex'}).waitFor();
  await entry.getByText('Experimentrevisionen (2)',{exact:true}).click();
  const latestRevision = rows[reviewed].evidence_index.experiments[0].revisions[1];
  await entry.getByText(latestRevision.sha256,{exact:true}).waitFor();
  await page.locator('#proof-rows').selectOption(String(rows.findIndex(row => row.status === 'hint')));
  await entry.getByText('Kein Experiment mit diesem Befund verknüpft.',{exact:true}).waitFor();
  await page.locator('#proof-clear').click();
  const altered = structuredClone(cockpitFixture.proof.handover);
  altered.report.counts.not_retested = 0;
  await page.locator('#proof-package').setInputFiles(file('tampered.json',altered));
  await page.locator('#proof-key').setInputFiles(file('trust.json',cockpitFixture.trustedKey));
  await hero.locator('#beweis-cockpit button').click();
  await page.locator('#proof-status[data-error=true]').waitFor();
  assert(await page.locator('#proof-result').isHidden());
}

function routeLinks(scope, pathname) {
  const relative = pathname.slice(1);
  return scope.locator(`a[href="${pathname}"]:visible, a[href="${relative}"]:visible`);
}

async function checkFits(page, locator, label) {
  await locator.scrollIntoViewIfNeeded();
  const bounds = await locator.boundingBox();
  const {width, height} = page.viewportSize();
  assert(bounds && bounds.width > 0 && bounds.height > 0, label + ' has no visible area');
  assert(bounds.x >= -1 && bounds.x + bounds.width <= width + 1, label + ' overflows horizontally');
  assert(bounds.y < height && bounds.y + bounds.height > 0, label + ' is outside the viewport');
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
    label + ' causes horizontal page overflow');
}

async function verifyHomepagePaths(page, origin, width) {
  await page.goto(origin);
  const hero = page.locator('section').filter({has: page.getByRole('heading', {level: 1})}).first();
  assert.equal(await hero.locator('#cockpit, #finding-select').count(), 0);
  await verifySignedCockpit(page, hero);
  for (const destination of ['/workbench/', '/downloads/#team']) {
    const action = routeLinks(hero, destination).first();
    await checkFits(page, action, destination);
    await action.click();
    await page.waitForURL(origin + destination);
    if (destination.includes('#team')) assert(await page.locator('#team').isVisible());
    await page.goto(origin);
  }
  const startTools = hero.locator('a[href$="#werkzeuge"]');
  await checkFits(page, startTools, 'Hero tools action');
  await startTools.click();
  await page.waitForURL(url => url.hash === '#werkzeuge');
  const tools = ['/dateipruefung/', '/rbac/', '/import/', '/workbench/'];
  const destinations = [...tools, '/fachzugang/', '/downloads/', '/abos/'];
  for (const pathname of destinations) {
    await page.goto(origin);
    const scope = tools.includes(pathname) ? page.locator('#werkzeuge') : page.locator('body');
    const candidates = routeLinks(scope, pathname);
    assert(await candidates.count() > 0, `No visible link to ${pathname} at ${width}px`);
    const link = candidates.first();
    assert((await link.innerText()).trim() || (await link.getAttribute('aria-label'))?.trim(),
      'Link needs an accessible name: ' + pathname);
    await checkFits(page, link, pathname);
    const [response] = await Promise.all([page.waitForNavigation(), link.click()]);
    assert.equal(response?.status(), 200, pathname);
    assert.equal(page.url(), origin + pathname);
    assert(await page.getByRole('heading', {level: 1}).isVisible(), pathname);
  }
  await page.goto(origin);
  const nav = width < 500 ? page.locator('.mobile-nav nav') : page.locator('.wide-nav');
  if (width < 500) {
    assert(!await nav.isVisible(), 'Mobile menu starts collapsed');
    await page.locator('.mobile-nav summary').click();
  }
  for (const pathname of ['/workbench/', '/downloads/', '/fachzugang/', '/abos/', '/lab.html']) {
    const entry = routeLinks(nav, pathname);
    await checkFits(page, entry, 'Navigation ' + pathname);
    await entry.click({trial: true});
  }
  const toolsLink = nav.locator('a[href$="#werkzeuge"]:visible').first();
  await checkFits(page, toolsLink, 'Navigation to tools');
  await toolsLink.click();
  await page.waitForURL(url => url.hash === '#werkzeuge');
  assert(await page.locator('#werkzeuge').evaluate(section => {
    const box = section.getBoundingClientRect();
    return box.top < innerHeight && box.bottom > 0;
  }), 'Tools section is in view after menu navigation');
}

module.exports = {checkFits, routeLinks, verifyHomepagePaths};
