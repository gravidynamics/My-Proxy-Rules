/*
 * Po0 Firewall Auto-Whitelist
 * Compatible with: Surge / Stash / Shadowrocket / Loon / Quantumult X
 * (Egern uses a different runtime model; use the dedicated
 * egern/po0-firewall-whitelist.js script.)
 *
 * POST /api/firewall/<token>/add adds the current request's source IP
 * to the whitelist and returns:
 *   {enabled, whitelist:[{ip,slot}], limit, currentIp}.
 * The token is passed in the URL path, so no Authorization header is required.
 *
 * The server handles duplicate IPs idempotently: an IP already in the whitelist
 * will not occupy an additional slot or advance the eviction queue. Therefore,
 * this script can issue the request on every run without checking first.
 *
 * Whitelisting is performed at the /24 subnet level. The server normalizes both
 * whitelist entries and currentIp to x.x.x.0/24 in its response. Changing IPs
 * within the same /24 subnet does not create a new entry. The script uses
 * sameC24() for matching, ensuring compatibility with mixed formats from
 * older and newer API versions.
 *
 * When the whitelist is full, the oldest slotless entry is automatically
 * evicted according to FIFO. The API does not provide an endpoint for manual
 * removal.
 *
 * Strategy:
 * - POST the current public IP on every run, regardless of whether the connection
 *   is cellular, Wi-Fi, or wired.
 * - By default, entries are slotless and subject to FIFO eviction. Evicted
 *   devices are expected to re-register automatically within a few minutes
 *   through their own cron jobs or network-change triggers.
 * - Optional pinned slots: append @N to the token (e.g. pgnfw_xxx@0) to pin
 *   this device's IP to slot N using POST .../add?slot=N.
 *   Slot assignment behavior:
 *     - If the current IP is already in the requested slot, refresh updated_at.
 *     - If the slot contains an old IP, replace that entry and discard the old IP.
 *     - If the current IP is already registered as slotless, remove that entry
 *       and promote it to the requested slot.
 *     - If the current IP is already assigned to a different slot, return HTTP 403.
 *       The existing slot must first be removed through the web UI.
 *       The script reports this conflict as an error.
 * - IPs registered over a cellular connection (primary interface pdp_ip*)
 *   are marked with 🛰️ for identification in the dashboard.
 *
 * Token configuration (highest priority first):
 * 1. argument: tokens=<pgnfw_xxx>[@slot],<pgnfw_yyy>
 *    (module arguments in Surge / Loon / Stash / Shadowrocket)
 * 2. Persistent storage key "Po0fw_tokens"
 *    (for clients such as Quantumult X that do not support arguments;
 *     the value can be written using BoxJs or a one-time script)
 * 3. INLINE_TOKENS below
 *    (fill this in directly when maintaining a custom copy of the script)
 */

/* ---------- Execution Diagnostics ---------- */

console.log(
  "[Po0] Script started",
  JSON.stringify({
    name: $script.name,
    type: $script.type,
    event: typeof $event !== "undefined" ? $event.name : null,
    trigger: typeof $trigger !== "undefined" ? $trigger : null,
    argument: typeof $argument !== "undefined" ? $argument : null,
    network: $network
  })
);

var INLINE_TOKENS = "";

var API_BASE = "https://124.221.69.228/api/firewall/"; // + <token> + "/add"
var STORE_PREFIX = "Po0_fw_";
var TOKENS_KEY = "Po0fw_tokens";
var HIST_WINDOW_MS = 7 * 24 * 3600 * 1000; // 🛰️ Cellular activity tracking window (7 days)

/* ---------- Runtime Compatibility Layer ---------- */

var isQX = typeof $task !== "undefined";
var isSurgeLike = typeof $httpClient !== "undefined"; // Surge / Stash / Shadowrocket / Loon

// Client identification: each client exposes a different runtime identifier.
// Loon provides the global $loon object, while Surge-family clients expose
// fields such as surge-version and shadowrocket-version through $environment.
var envInfo = "";
try {
  if (typeof $environment !== "undefined" && $environment) {
    envInfo = JSON.stringify($environment).toLowerCase();
  }
} catch (e) {}

var isLoon = typeof $loon !== "undefined" || envInfo.indexOf("loon") >= 0;
var isSurgeFamily =
  envInfo.indexOf("surge-version") >= 0 ||
  envInfo.indexOf("shadowrocket") >= 0 ||
  envInfo.indexOf("stash") >= 0;

// ⚠️ Timeout units differ between clients:
//   Surge / Shadowrocket / Stash → seconds
//   Loon / Quantumult X          → milliseconds
// Hardcoding 15 would make Loon wait only 15 milliseconds, causing an almost
// immediate timeout. Its callback may even return error=null, resulting in
// an uninformative "(null)" error message.
// If the client cannot be identified, omit the timeout and let the module-level
// timeout=60 serve as a fallback, avoiding this unit mismatch.
var REQUEST_TIMEOUT = null;
if (isLoon || isQX) REQUEST_TIMEOUT = 15000;
else if (isSurgeFamily) REQUEST_TIMEOUT = 15;

function storeRead(key) {
  try {
    if (isQX) return $prefs.valueForKey(key);
    if (typeof $persistentStore !== "undefined") return $persistentStore.read(key);
  } catch (e) {}
  return null;
}

function storeWrite(value, key) {
  try {
    if (isQX) return $prefs.setValueForKey(value, key);
    if (typeof $persistentStore !== "undefined") return $persistentStore.write(value, key);
  } catch (e) {}
  return false;
}

function notify(title, subtitle, body) {
  try {
    if (isQX) $notify(title, subtitle, body);
    else if (typeof $notification !== "undefined") $notification.post(title, subtitle, body);
  } catch (e) {}
}

function safeDecodeURIComponent(s) {
  try {
    return decodeURIComponent(s);
  } catch (e) {
    return s;
  }
}

// HTTP errors returned by different clients vary considerably. Loon may invoke
// the callback with error=null during a network interruption or TLS handshake
// failure. Simply calling String(null) would produce an uninformative "null".
function describeHttpError(error) {
  var text;
  if (error === null || error === undefined) text = "";
  else if (typeof error === "object")
    text = String(error.message || error.error || error.description || "");
  else text = String(error);
  text = text.replace(/^\s+|\s+$/g, "");
  if (text === "" || text === "null" || text === "undefined" || text === "{}") {
    return "Network request failed (timeout / handshake failure / blocked)";
  }
  return text;
}

function httpRequestOnce(method, opts) {
  return new Promise(function (resolve) {
    if (isQX) {
      opts.method = method;
      $task.fetch(opts).then(
        function (resp) {
          resolve({ body: resp.body, status: resp.statusCode });
        },
        function (err) {
          resolve({ error: describeHttpError((err && err.error) || err) });
        }
      );
    } else if (isSurgeLike) {
      // Do not detach $httpClient.post from its owning object and invoke it
      // through a local variable. Shadowrocket exposes $httpClient as an
      // Objective-C bridged object, and detached invocation may throw:
      // "self type check failed for Objective-C instance method".
      // Always call the method directly on $httpClient.
      var cb = function (error, response, body) {
        if (error) resolve({ error: describeHttpError(error) });
        else resolve({ body: body, status: response && (response.status || response.statusCode) });
      };
      if (method === "POST") $httpClient.post(opts, cb);
      else $httpClient.get(opts, cb);
    } else {
      resolve({ error: "unsupported client" });
    }
  });
}

function delay(ms) {
  return new Promise(function (resolve) {
    if (typeof setTimeout === "function") setTimeout(resolve, ms);
    else resolve();
  });
}

// A single request may fail on mobile networks, especially when a cron job
// runs just as the network becomes active or during a network transition.
// The server handles duplicate IPs idempotently, so retrying POST /add will
// not occupy additional slots or advance the eviction queue.
var HTTP_RETRY = 3;
var HTTP_RETRY_DELAY_MS = 1500;

// Transient server-side errors are also worth retrying. The Po0 API occasionally
// returns a bare HTTP 400 response (with a body containing only "Error") or a
// 5xx response, while the same request may succeed a few seconds later.
// Well-formed JSON errors (such as {"code":400,...} for an invalid token)
// are deterministic failures and should not be retried.
function isRetryableServerError(r) {
  if (!r || !r.status) return false;
  if (r.status >= 500 || r.status === 429) return true;
  if (r.status >= 200 && r.status < 300) return false;
  if (r.status === 403) return false; // Slot conflict; retrying will not help.
  try {
    JSON.parse(r.body);
    return false; // A well-formed JSON error indicates a deterministic failure.
  } catch (e) {
    return true; // A non-JSON body (such as a bare "Error") may indicate a transient failure.
  }
}

function httpRequest(method, opts, attempt) {
  attempt = attempt || 1;
  return httpRequestOnce(method, opts).then(function (r) {
    if (!r.error && !isRetryableServerError(r)) return r;
    if (attempt >= HTTP_RETRY) {
      if (r.error) r.error = r.error + " (retried " + HTTP_RETRY + " times)";
      else r.retried = HTTP_RETRY;
      return r;
    }
    return delay(HTTP_RETRY_DELAY_MS * attempt).then(function () {
      return httpRequest(method, opts, attempt + 1);
    });
  });
}

function getArgumentTokens() {
  if (typeof $argument === "undefined" || $argument === null) return "";
  // Loon plugins may inject arguments as an object: {tokens: "..."}.
  if (typeof $argument === "object") return String($argument.tokens || "");
  if (typeof $argument === "string") {
    var arg = $argument.replace(/^\s+|\s+$/g, "");
    if (!arg) return "";
    // Some clients, such as Shadowrocket, may preserve the surrounding quotes
    // from the configuration. Strip them before parsing.
    if (/^["'].*["']$/.test(arg)) arg = arg.slice(1, -1).replace(/^\s+|\s+$/g, "");
    // Loon may also inject arguments as a JSON string.
    if (arg.charAt(0) === "{") {
      try {
        return String(JSON.parse(arg).tokens || "");
      } catch (e) {}
    }
    // Surge / Stash style: tokens=xxx&...
    var pairs = arg.split("&");
    for (var i = 0; i < pairs.length; i++) {
      var idx = pairs[i].indexOf("=");
      if (idx > 0 && pairs[i].slice(0, idx).replace(/^\s+|\s+$/g, "") === "tokens") {
        return safeDecodeURIComponent(pairs[i].slice(idx + 1).replace(/^\s+|\s+$/g, ""));
      }
    }
    // Fallback: treat the entire string as a token
    // (e.g. Loon argument="pgnfw_...").
    if (arg.indexOf("pgnfw_") === 0) return arg;
  }
  return "";
}

function parseTokenEntries(raw) {
  return String(raw || "")
    .split(/[,，|;、\s]+/)
    .map(function (s) {
      return s.replace(/^\s+|\s+$/g, "");
    })
    .filter(function (s) {
      return s.indexOf("pgnfw_") === 0;
    })
    .map(function (s) {
      var at = s.indexOf("@");
      if (at === -1) return { token: s, slot: null, invalidError: null };
      var tok = s.slice(0, at);
      var slotRaw = s.slice(at + 1);
      if (!/^\d+$/.test(slotRaw)) {
        return {
          token: tok,
          slot: null,
          invalidError: "Invalid slot suffix '@" + slotRaw + "' (must be numeric, e.g. @0)",
        };
      }
      return { token: tok, slot: parseInt(slotRaw, 10), invalidError: null };
    })
    .filter(function (item) {
      // Ignore unreplaced Chinese placeholders (e.g. "pgnfw_你的token").
      if (/[^\x20-\x7E]/.test(item.token)) return false;
      if (!/^pgnfw_[A-Za-z0-9_-]+$/.test(item.token) && !item.invalidError) {
        item.invalidError = "Token contains invalid characters";
      }
      return true;
    });
}

function onCellular() {
  try {
    var iface =
      ($network.v4 && $network.v4.primaryInterface) ||
      ($network.v6 && $network.v6.primaryInterface) ||
      "";
    return iface.indexOf("pdp_ip") === 0;
  } catch (e) {
    return false; // Treat as non-cellular if $network is unavailable.
  }
}

function finish(title, content, allOk) {
  if (isQX) {
    $done();
    return;
  }
  $done({
    title: title,
    content: content,
    icon: allOk ? "checkmark.shield" : "exclamationmark.shield",
    "icon-color": allOk ? "#34C759" : "#FF3B30",
  });
}

/* ---------- Core Logic ---------- */

// The server registers IPs at the /24 subnet level. Entries may be exact IP
// addresses or x.x.x.0/24 subnets.
// If either side is a /24 subnet, compare the first three octets.
// If both sides are exact IP addresses, require an exact match.
function sameC24(a, b) {
  if (!a || !b) return false;
  a = String(a);
  b = String(b);
  if (a === b) return true;
  if (a.slice(-3) !== "/24" && b.slice(-3) !== "/24") return false;
  var pa = a.replace("/24", "").split(".");
  var pb = b.replace("/24", "").split(".");
  return (
    pa.length === 4 && pb.length === 4 && pa[0] === pb[0] && pa[1] === pb[1] && pa[2] === pb[2]
  );
}

function readHistory(key) {
  try {
    var h = JSON.parse(storeRead(key) || "[]");
    if (!Array.isArray(h)) return [];
    var cutoff = Date.now() - HIST_WINDOW_MS;
    return h.filter(function (e) {
      return e && e.ts > cutoff;
    });
  } catch (e) {
    return [];
  }
}

function apiCall(token, slot) {
  // The token is passed in the URL path. Calling /add registers the current
  // public IP; adding a slot parameter pins the IP to a fixed slot.
  var url = API_BASE + encodeURIComponent(token) + "/add";
  if (slot !== null && slot !== undefined && slot !== "") {
    url += "?slot=" + encodeURIComponent(slot);
  }
  var opts = {
    url: url,
    headers: { "Content-Type": "application/json" },
    body: "",
  };
  if (REQUEST_TIMEOUT !== null) opts.timeout = REQUEST_TIMEOUT;

  return httpRequest("POST", opts).then(function (r) {
    if (r.error) return { error: r.error };
    var data = null;
    try {
      data = JSON.parse(r.body);
    } catch (e) {}
    // When the local IP is already assigned to another slot, a pinned-slot
    // registration returns HTTP 403. The existing slot must be removed
    // through the web UI first.
    if (r.status === 403) {
      return {
        error: "Slot conflict: this IP is already assigned to another slot. Remove the existing assignment in the web UI first.",
        conflict: true,
        currentIp: data && data.currentIp,
      };
    }
    var errStatus = r.status && (r.status < 200 || r.status >= 300) ? r.status : 0;
    if (!errStatus && data && typeof data.code === "number" && data.code >= 400) {
      errStatus = data.code;
    }
    if (errStatus) {
      var msg =
        (data && (data.message || data.error)) ||
        String(r.body || "").replace(/^\s+|\s+$/g, "").slice(0, 80) ||
        "Request rejected";
      var retrySuffix = r.retried ? " (retried " + r.retried + " times)" : "";
      return { error: "HTTP " + errStatus + ": " + msg + retrySuffix };
    }
    if (!data || (typeof data !== "object")) {
      return { error: "Invalid response: " + String(r.body).slice(0, 80) };
    }
    // Whitelist entries are objects of the form {ip, slot} (older versions
    // returned plain IP strings). Record the IP-to-slot mapping, then flatten
    // the whitelist into an array of IP addresses.
    var raw = Array.isArray(data.whitelist) ? data.whitelist : [];
    data.slotOf = {};
    raw.forEach(function (e) {
      if (e && typeof e === "object" && e.slot !== null && e.slot !== undefined) {
        data.slotOf[e.ip] = e.slot;
      }
    });
    data.whitelist = raw.map(function (e) {
      return e && typeof e === "object" ? e.ip : e;
    });
    data.applied =
      data.enabled === true &&
      data.whitelist.some(function (ip) {
        return sameC24(ip, data.currentIp);
      });
    return data;
  });
}

function ensureWhitelisted(item, index) {
  var kvState = STORE_PREFIX + index;
  var kvHist = STORE_PREFIX + "hist_" + index;
  var cellular = onCellular();
  var ctx = { kvState: kvState, kvHist: kvHist, slot: item.slot };

  if (item.invalidError) {
    ctx.st = { error: item.invalidError };
    return Promise.resolve(ctx);
  }

  // The server handles duplicate IPs idempotently, so call /add directly
  // without checking the existing whitelist first.
  return apiCall(item.token, item.slot).then(function (st) {
    if (st.applied) {
      var hist = readHistory(kvHist);
      var last = hist.length ? hist[hist.length - 1] : null;
      if (!last || last.ip !== st.currentIp) {
        hist.push({ ip: st.currentIp, src: cellular ? "cell" : "fixed", ts: Date.now() });
        storeWrite(JSON.stringify(hist.slice(-10)), kvHist);
      }
    }
    ctx.st = st;
    return ctx;
  });
}

function isCellIpInHistory(hist, ip) {
  for (var i = 0; i < hist.length; i++) {
    if (hist[i].src === "cell" && sameC24(hist[i].ip, ip)) return true;
  }
  return false;
}

// One entry per token. Stored data excludes the token and contains only
// whitelist and slot information. Cellular IPs are marked with 🛰️.
function describe(index, ctx) {
  var st = ctx.st;
  var pin = ctx.slot !== null && ctx.slot !== undefined && ctx.slot !== "" ? " ⛰️" + ctx.slot : "";
  var head = "#" + (index + 1) + pin + " ";
  if (st.error) return head + "🗻 " + st.error;
  if (st.enabled === false) return head + "⚠️ Firewall is disabled";
  var limit = st.limit || 5;
  var list = Array.isArray(st.whitelist) ? st.whitelist : [];
  if (!st.applied) return head + "🗻 Whitelisting failed " + list.length + "/" + limit;

  var hist = readHistory(ctx.kvHist);
  var slotOf = st.slotOf || {};
  var ips = list
    .map(function (ip) {
      var slotTag = slotOf[ip] !== undefined ? " ⛰️" + slotOf[ip] : "";
      var cellTag = isCellIpInHistory(hist, ip) ? " 🛰️" : "";
      return ip + slotTag + cellTag + (sameC24(ip, st.currentIp) ? " ←" : "");
    })
    .join("\n    ");
  return head + "🌋 " + list.length + "/" + limit + "\n    " + ips;
}

(function main() {
  try {
    var tokens = parseTokenEntries(getArgumentTokens() || storeRead(TOKENS_KEY) || INLINE_TOKENS || "");

    if (tokens.length === 0) {
      notify(
        "Po0 Firewall Whitelist",
        "No token configured",
        "Configure a pgnfw_ token using one of these options: module argument 'tokens', persistent storage key 'Po0fw_tokens', or the INLINE_TOKENS constant in the script."
      );
      finish("Po0 Whitelist: No Token Configured", "Please provide a pgnfw_ token. Separate multiple tokens with , or |.", false);
      return;
    }

    Promise.all(
      tokens.map(function (t, i) {
        return ensureWhitelisted(t, i);
      })
    )
      .then(function (results) {
        var okCount = 0;
        var exitIp = "?";
        var lines = [];
        var changed = false;

        for (var i = 0; i < results.length; i++) {
          var st = results[i].st;
          if (st.applied) okCount++;
          if (st.currentIp) exitIp = st.currentIp;
          lines.push(describe(i, results[i]));

          var slotKey =
            results[i].slot !== null && results[i].slot !== undefined ? String(results[i].slot) : "-";
          var state = (st.currentIp || "?") + "|" + (st.applied ? "1" : "0") + "|" + slotKey;
          if (storeRead(results[i].kvState) !== state) {
            storeWrite(state, results[i].kvState);
            changed = true;
          }
        }

        var allOk = okCount === results.length;
        var title =
          "Po0 Whitelist " +
          okCount +
          "/" +
          results.length +
          " · Exit IP " +
          exitIp +
          (onCellular() ? " 🛰️" : "");
        var content = lines.join("\n");

        // Notify on successful runs only when the exit IP, whitelist status,
        // or slot assignment changes. Always notify on failures or unsuccessful
        // whitelisting; otherwise, a repeated failure with unchanged persisted
        // state would be silently suppressed because changed would be false.
        if (changed || !allOk) {
          notify("Po0 Firewall Whitelist", title, content);
        }
        finish(title, content, allOk);
      })
      .catch(function (e) {
        var msg = String(e && e.message ? e.message : e);
        notify("Po0 Firewall Whitelist", "Script error", msg);
        finish("Po0 Whitelist: Script Error", msg, false);
      });
  } catch (e) {
    var msg = String(e && e.message ? e.message : e);
    notify("Po0 Firewall Whitelist", "Script error", msg);
    finish("Po0 Whitelist: Script Error", msg, false);
  }
})();
