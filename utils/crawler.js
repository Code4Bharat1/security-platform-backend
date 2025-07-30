import axios from 'axios';
import * as cheerio from 'cheerio';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const crawlWebsite = async (startUrl, maxDepth = 3) => {
  const visited = new Set();
  const queue = [{ url: startUrl, depth: 0 }];

  const domain = new URL(startUrl).hostname;
  const result = [];

  while (queue.length > 0) {
    const { url, depth } = queue.shift();

    if (visited.has(url) || depth > maxDepth) continue;

    visited.add(url);

    try {
      const res = await axios.get(url);
      result.push(url);

      const $ = cheerio.load(res.data);
      $('a[href]').each((_, el) => {
        let link = $(el).attr('href');
        try {
          link = new URL(link, url).href;
          const linkDomain = new URL(link).hostname;
          if (linkDomain === domain && !visited.has(link)) {
            queue.push({ url: link, depth: depth + 1 });
          }
        } catch {
          // invalid url, skip
        }
      });

      await sleep(300); // Respect servers
    } catch (err) {
      console.warn(`Failed to crawl ${url}:`, err.message);
    }
  }

  return result;
};

export default crawlWebsite;
