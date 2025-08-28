// controllers/osintController.js
import dns from "dns";
import crypto from "crypto";
import fetch from "node-fetch";
import OsintResult from "../models/OsintResult.js";

const dnsAsync = dns.promises;

// ---------- Shared helpers ----------
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36";

const fetchWithTimeout = async (url, { timeoutMs = 8000, headers = {} } = {}) => {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": UA, Accept: "text/html,application/xhtml+xml", ...headers },
      redirect: "follow",
      signal: controller.signal,
    });
    const text = await res.text();
    return { status: res.status, text, headers: res.headers };
  } finally {
    clearTimeout(t);
  }
};

const emailToMd5 = (email) =>
  crypto.createHash("md5").update(email.trim().toLowerCase()).digest("hex");

const normalizePhone = (p) => p.replace(/[^\d+]/g, "");

// ---------- Username checks ----------
const usernameSites = [
  {
    name: "GitHub",
    buildUrl: (u) => `https://github.com/${u}`,
    notFoundMatch: /not found|there isn’t a GitHub page|page not found/i,
    okStatuses: [200],
  },
  {
    name: "Twitter (X)",
    buildUrl: (u) => `https://x.com/${u}`,
    notFoundMatch: /account doesn.?t exist|page doesn.?t exist/i,
    okStatuses: [200],
  },
  {
    name: "Reddit",
    buildUrl: (u) => `https://www.reddit.com/user/${u}/`,
    notFoundMatch: /page not found|nobody on reddit goes by that name/i,
    okStatuses: [200],
  },
  {
    name: "Instagram",
    buildUrl: (u) => `https://www.instagram.com/${u}/`,
    notFoundMatch: /sorry, this page isn.?t available/i,
    okStatuses: [200],
  },
  {
    name: "TikTok",
    buildUrl: (u) => `https://www.tiktok.com/@${u}`,
    notFoundMatch: /couldn.?t find this account|doesn.?t exist|404/i,
    okStatuses: [200],
  },
  {
    name: "Pinterest",
    buildUrl: (u) => `https://www.pinterest.com/${u}/`,
    notFoundMatch: /couldn.?t find that page|404/i,
    okStatuses: [200],
  },
  {
    name: "Tumblr",
    buildUrl: (u) => `https://${u}.tumblr.com/`,
    notFoundMatch: /there.?s nothing here|not found|can.?t find that page/i,
    okStatuses: [200],
  },
  {
    name: "LinkedIn",
    buildUrl: (u) => `https://www.linkedin.com/in/${u}/`,
    notFoundMatch: /profile not found|doesn.?t exist/i,
    okStatuses: [200],
    treatForbiddenAsUnknown: true, // 403/999 often due to bot protection
  },
];

const checkUsernameAcrossSites = async (username) => {
  const results = await Promise.all(
    usernameSites.map(async (site) => {
      const url = site.buildUrl(username);
      try {
        const { status, text } = await fetchWithTimeout(url);
        if (status === 404) return { platform: site.name, url, status: "not_found" };
        if (site.treatForbiddenAsUnknown && (status === 403 || status === 999)) {
          return { platform: site.name, url, status: "unknown", note: "Access blocked" };
        }
        if (site.okStatuses.includes(status)) {
          if (site.notFoundMatch && site.notFoundMatch.test(text)) {
            return { platform: site.name, url, status: "not_found" };
          }
          return { platform: site.name, url, status: "found" };
        }
        if (status >= 200 && status < 300) return { platform: site.name, url, status: "found" };
        if ([301, 302, 307, 308].includes(status))
          return { platform: site.name, url, status: "unknown", note: `Redirect ${status}` };
        if (status === 403) return { platform: site.name, url, status: "unknown", note: "Forbidden" };
        return { platform: site.name, url, status: "unknown" };
      } catch (e) {
        return { platform: site.name, url, status: "error", error: e.message };
      }
    })
  );
  return results;
};

// ---------- Email checks ----------
const checkEmailDns = async (email) => {
  const platform = "DNS/MX";
  try {
    const parts = email.split("@");
    const domain = parts[1];
    if (!domain) return { platform, url: null, status: "invalid", note: "Missing domain" };

    let hasAny = false;
    try {
      await dnsAsync.resolve(domain);
      hasAny = true;
    } catch {}

    let mx = [];
    try {
      mx = await dnsAsync.resolveMx(domain);
    } catch {}

    if (mx.length > 0) {
      return {
        platform,
        url: `mailto:${email}`,
        status: "found",
        note: `MX records present (${mx.length})`,
      };
    }
    if (hasAny) {
      return {
        platform,
        url: `mailto:${email}`,
        status: "unknown",
        note: "Domain resolves but no MX",
      };
    }
    return { platform, url: `mailto:${email}`, status: "not_found", note: "Domain does not resolve" };
  } catch (e) {
    return { platform, url: null, status: "error", error: e.message };
  }
};

const checkEmailGravatar = async (email) => {
  const hash = emailToMd5(email);
  const url = `https://www.gravatar.com/avatar/${hash}?d=404`;
  try {
    const res = await fetchWithTimeout(url);
    if (res.status === 200) return { platform: "Gravatar", url, status: "found" };
    if (res.status === 404) return { platform: "Gravatar", url, status: "not_found" };
    return { platform: "Gravatar", url, status: "unknown" };
  } catch (e) {
    return { platform: "Gravatar", url, status: "error", error: e.message };
  }
};

const checkEmailLibravatar = async (email) => {
  const hash = emailToMd5(email);
  const url = `https://seccdn.libravatar.org/avatar/${hash}?d=404`;
  try {
    const res = await fetchWithTimeout(url);
    if (res.status === 200) return { platform: "Libravatar", url, status: "found" };
    if (res.status === 404) return { platform: "Libravatar", url, status: "not_found" };
    return { platform: "Libravatar", url, status: "unknown" };
  } catch (e) {
    return { platform: "Libravatar", url, status: "error", error: e.message };
  }
};

const checkEmailRep = async (email) => {
  const url = `https://emailrep.io/${encodeURIComponent(email)}`;
  try {
    const apikey = process.env.EMAILREP_API_KEY || "";
    const headers = apikey
      ? { Key: apikey, "User-Agent": "osint-checker/1.0" }
      : { "User-Agent": "osint-checker/1.0" };
    const res = await fetchWithTimeout(url, { headers });
    if (res.status === 200) {
      let data;
      try {
        data = JSON.parse(res.text);
      } catch {}
      const rep = data?.reputation || "unknown";
      const refs = Array.isArray(data?.references) ? data.references.length : 0;
      return {
        platform: "EmailRep.io",
        url,
        status: "found",
        note: `reputation: ${rep}, references: ${refs}`,
      };
    }
    if (res.status === 404) return { platform: "EmailRep.io", url, status: "not_found" };
    if ([401, 403, 429].includes(res.status))
      return { platform: "EmailRep.io", url, status: "unknown", note: `API ${res.status}` };
    return { platform: "EmailRep.io", url, status: "unknown" };
  } catch (e) {
    return { platform: "EmailRep.io", url, status: "error", error: e.message };
  }
};

const checkHibpBreaches = async (email) => {
  const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(
    email
  )}?truncateResponse=true`;
  const headers = {
    "hibp-api-key": process.env.HIBP_API_KEY || "",
    "user-agent": "osint-checker/1.0",
  };
  try {
    const res = await fetchWithTimeout(url, { headers, timeoutMs: 10000 });
    if (res.status === 200) {
      let data;
      try {
        data = JSON.parse(res.text);
      } catch {}
      const names = Array.isArray(data) ? data.map((b) => b.Name).slice(0, 5) : [];
      return {
        platform: "HaveIBeenPwned",
        url: "https://haveibeenpwned.com/",
        status: "found",
        note: names.length ? `breaches: ${names.join(", ")}` : "breaches found",
      };
    }
    if (res.status === 404)
      return { platform: "HaveIBeenPwned", url: "https://haveibeenpwned.com/", status: "not_found" };
    if ([401, 403, 429].includes(res.status))
      return {
        platform: "HaveIBeenPwned",
        url: "https://haveibeenpwned.com/",
        status: "unknown",
        note: `API ${res.status} (key/rate limit)`,
      };
    return { platform: "HaveIBeenPwned", url: "https://haveibeenpwned.com/", status: "unknown" };
  } catch (e) {
    return {
      platform: "HaveIBeenPwned",
      url: "https://haveibeenpwned.com/",
      status: "error",
      error: e.message,
    };
  }
};

// ---------- Main controller ----------
export const checkOsint = async (req, res) => {
  try {
    const { username, email, phone } = req.body || {};

    let queryType = "";
    let queryValue = "";
    let details = [];

    if (username && username.trim()) {
      queryType = "username";
      queryValue = username.trim();
      details = await checkUsernameAcrossSites(queryValue);
    } else if (email && email.trim()) {
      queryType = "email";
      queryValue = email.trim();

      const [dnsMx, grav, lib, rep, hibp] = await Promise.all([
        checkEmailDns(queryValue),
        checkEmailGravatar(queryValue),
        checkEmailLibravatar(queryValue),
        checkEmailRep(queryValue),
        checkHibpBreaches(queryValue),
      ]);
      details = [dnsMx, grav, lib, rep, hibp];
    } else if (phone && phone.trim()) {
      queryType = "phone";
      queryValue = normalizePhone(phone);

      // Public, free phone existence checks aren’t reliable; provide honest output.
      details = [
        {
          platform: "Phone Lookup",
          url: null,
          status: /^\+?\d{8,15}$/.test(queryValue) ? "unknown" : "invalid",
          note:
            "Direct phone OSINT checks require paid APIs; only basic format validation done.",
        },
      ];
    } else {
      return res
        .status(400)
        .json({ success: false, message: "Provide username, email, or phone to scan." });
    }

    const foundOn = details.filter((d) => d.status === "found").map((d) => d.platform);

    // Persist
    const result = new OsintResult({
      queryType,
      queryValue,
      foundOn,
      details, // make sure your schema has this field (Array)
    });
    await result.save();

    return res.json({
      success: true,
      queryType,
      queryValue,
      foundOn,
      details,
      checkedAt: result.checkedAt,
    });
  } catch (err) {
    console.error("OSINT error:", err);
    res.status(500).json({ success: false, message: "Server error during OSINT scan" });
  }
};
