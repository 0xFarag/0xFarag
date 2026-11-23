// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';

const assert = require('node:assert/strict');

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
  assert(await hero.locator('#cockpit #finding-select').isVisible(), 'Interactive cockpit is in the hero');
  const offlinePath = '/downloads/pruefwerkzeuge/AuthzLedger-Offline-Pruefwerkzeuge.zip';
  const offline = routeLinks(hero, offlinePath);
  await checkFits(page, offline, 'Hero offline ZIP');
  const [download] = await Promise.all([page.waitForEvent('download'), offline.click()]);
  assert.equal(download.suggestedFilename(), offlinePath.split('/').pop());
  assert.equal(await download.failure(), null);
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
