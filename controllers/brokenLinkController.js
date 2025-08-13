import { parse } from 'node-html-parser';
import fetch from 'node-fetch';
import { BrokenLinkScan } from '../models/brokenLinkModel.js';

export const streamBrokenLinks = async (req, res) => {
  const url = req.query.url;

  if (!url) {
    return res.status(400).json({ type: 'error', message: 'URL is required' });
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  try {
    const htmlResponse = await fetch(url);
    const html = await htmlResponse.text();

    const root = parse(html);
    const anchorTags = root.querySelectorAll('a');
    const links = anchorTags
      .map(a => a.getAttribute('href'))
      .filter(link => link && (link.startsWith("https") || link.startsWith('http')));

    res.write(`data: ${JSON.stringify({ type: 'total', total: links.length })}\n\n`);

    const results = []; // collect for DB

    for (let link of links) {
      try {
        const response = await fetch(link);
        const result = {
          url: link,
          status: response.status,
          ok: response.ok
        };

        results.push(result);

        res.write(`data: ${JSON.stringify({ type: 'link', ...result })}\n\n`);
      } catch (err) {
        const errorResult = {
          url: link,
          status: 'ERROR',
          ok: false
        };

        results.push(errorResult);

        res.write(`data: ${JSON.stringify({ type: 'link', ...errorResult })}\n\n`);
      }
    }

    // ✅ Save to MongoDB
    await BrokenLinkScan.create({
      scannedUrl: url,
      links: results
    });

    res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
    res.end();
    console.log(2)

  } catch (error) {
    res.write(`data: ${JSON.stringify({ type: 'error', message: error.message })}\n\n`);
    res.end();
    console.log(1)
  }
};
