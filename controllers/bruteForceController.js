// controllers/bruteForceController.js
import fetch from 'node-fetch';
import { BruteForceResult } from '../models/bruteForceModel.js';

const baseWordlist = [
  "/admin", "/login", "/dashboard", "/config", "/.git", "/.env", "/uploads",
  "/images", "/css", "/js", "/api", "/backup", "/db", "/test", "/old", "/dev",
  "/private", "/cgi-bin", "/scripts", "/phpmyadmin", "/webadmin", "/wp-admin",
  "/wp-login", "/cpanel", "/user", "/users", "/static", "/assets", "/logs",
  "/temp", "/tmp", "/bin"
];

const childWordlist = [
  "/", "/index.php", "/index.html",
  "/login", "/login.php",
  "/config", "/config.php", "/config.json", "/.env",
  "/users", "/admin", "/backup", "/backups", "/uploads", "/logs",
  "/install", "/setup", "/test", "/dev", "/old",
];

const looksLikeDir = (p) => {
  if (p.endsWith('/')) return true;
  const last = p.split('/').pop() || '';
  return !last.includes('.');
};
const joinPath = (base, extra) => {
  const a = base.endsWith('/') ? base.slice(0, -1) : base;
  const b = extra.startsWith('/') ? extra : `/${extra}`;
  return (a + b) || '/';
};

export const bruteForceScan = async (req, res) => {
  let { target, recursive = true, maxDepth = 2, concurrency = 6 } = req.body || {};
  try {
    if (!target || !/^https?:\/\//i.test(target)) {
      return res.status(400).json({ error: 'Invalid target URL' });
    }
    if (target.endsWith('/')) target = target.slice(0, -1);

    const startedAt = new Date();
    const results = [];
    const visited = new Set();
    let totalRequests = 0;
    let maxDepthReached = 0;
    let skippedDueToDepth = 0;

    // Simple concurrency pool
    const queue = [];
    let active = 0;
    const run = (fn) =>
      new Promise((resolve, reject) => {
        const task = async () => {
          active++;
          try {
            resolve(await fn());
          } catch (e) {
            reject(e);
          } finally {
            active--;
            if (queue.length) queue.shift()();
          }
        };
        if (active < concurrency) task();
        else queue.push(task);
      });

    const scheduleCheck = (urlPath, depth) =>
      run(async () => {
        const fullUrl = `${target}${urlPath}`;
        if (visited.has(fullUrl)) return;
        visited.add(fullUrl);

        totalRequests++;
        let status = 'Error';
        let label = '⚠️ Request Failed';

        try {
          const response = await fetch(fullUrl, { method: 'GET', redirect: 'manual' });
          status = response.status;

          if (status === 200) label = '✅ Accessible';
          else if (status === 403 || (status >= 300 && status < 400)) label = `⚠️ Possible - Status ${status}`;
          else label = '❌ Not Found';

          // record item with depth
          results.push({ path: urlPath, status, result: label, depth });

          // track depth stats
          if (depth > maxDepthReached) maxDepthReached = depth;

          // recurse if applicable
          if (recursive && looksLikeDir(urlPath) && (status === 200 || status === 403 || (status >= 300 && status < 400))) {
            for (const child of childWordlist) {
              const nextDepth = depth + 1;
              if (nextDepth > maxDepth) {
                skippedDueToDepth++;
                continue;
              }
              const next = joinPath(urlPath, child);
              if (next !== urlPath) {
                // schedule child (no await here; let the pool handle it)
                scheduleCheck(next, nextDepth);
              }
            }
          }
        } catch {
          results.push({ path: urlPath, status: 'Error', result: '⚠️ Request Failed', depth });
        }
      });

    // seed
    for (const p of baseWordlist) {
      scheduleCheck(p, 0);
    }

    // wait for pool completion
    await new Promise((resolve) => {
      const tick = setInterval(() => {
        if (active === 0 && queue.length === 0) {
          clearInterval(tick);
          resolve();
        }
      }, 50);
    });

    // persist (schema unchanged)
    await BruteForceResult.create({ target, results });

    const finishedAt = new Date();
    const durationMs = finishedAt - startedAt;

    return res.json({
      results,
      meta: {
        startedAt,
        finishedAt,
        durationMs,
        totalRequests,
        recursive: Boolean(recursive),
        maxDepth: Number(maxDepth),
        maxDepthReached,
        skippedDueToDepth,
        concurrency: Number(concurrency),
      },
    });
  } catch (error) {
    console.error('Scan failed:', error);
    return res.status(500).json({ error: 'Directory brute force scan failed' });
  }
};
