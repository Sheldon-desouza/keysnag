// Safe: Playwright's $eval/$$eval/.evaluate() helpers, not the eval() builtin.
// Must not fire injection.eval.
import type { Page } from "playwright";

export async function scrapeLinks(page: Page) {
  const rows = await page.$$eval("a", (els) => els.map((el) => el.textContent));
  const title = await page.$eval("h1", (el) => el.textContent);
  const count = await page.evaluate(() => document.querySelectorAll("a").length);
  return { rows, title, count };
}
