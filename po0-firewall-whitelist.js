/*
 * Po0 Firewall Auto-Whitelist
 * Compatible with: Surge / Stash / Shadowrocket / Loon / Quantumult X
 * (Egern uses a different runtime model; use the dedicated
 * egern/Po0-firewall-whitelist.js script.)
 *
 * POST /api/firewall/<token>/add
 *   Adds the current request's source IP to the whitelist and returns:
 *   {enabled, whitelist:[{ip,slot}], limit, currentIp}.
 *   The token is passed in the URL path, so no Authorization header is required.
 *
 *   The server handles duplicate IPs idempotently: an IP already in the whitelist
 *   will not occupy an additional slot or advance the eviction queue. Therefore,
 *   this script can issue the request on every run without checking first.
 *
 * Whitelisting is performed at the /24 subnet level. The server normalizes both
 * whitelist entries and currentIp to x.x.x.0/24 in its response. Changing IPs
 * within the same /24 subnet does not create a new entry. The sameC24() helper
 * handles both exact IP addresses and /24 subnet entries, allowing compatibility
 * with mixed formats from older and newer API versions.
 *
 * When the whitelist is full, the oldest slotless entry is evicted according to
 * its last update time (LRU). Devices that get evicted can automatically
 * re-register through their own cron jobs or network-change triggers.
 * The API does not provide an endpoint for manual removal.
 *
 * Strategy:
 * - POST the current public IP on every run, regardless of whether the connection
 *   is cellular, Wi-Fi, or wired.
 * - By default, entries are slotless and subject to LRU eviction based on
 *   updated_at. Evicted devices are expected to re-register automatically
 *   within a few minutes through their own cron jobs or event triggers.
 * - Optional pinned slots: append @N to the token (e.g. pgnfw_xxx@0) to pin this
 *   device's IP to slot N using POST .../add?slot=N.
 *   Pinned entries are never subject to LRU eviction.
 *
 *   Slot assignment behavior:
 *     - If the current IP is already in the requested slot, refresh updated_at.
 *     - If the slot contains another IP, replace that entry and discard the old IP.
 *     - If the current IP is already registered as slotless, remove that entry
 *       and promote it to the requested slot.
 *     - If the current IP is pinned to a different slot, return HTTP 403.
 *       The existing slot must first be removed through the web UI.
 *       The script reports this conflict as an error.
 *
 * - IPs registered over a cellular connection (primary interface pdp_ip*)
 *   are marked with 🛰️ for identification in the dashboard.
 *
 * Token configuration (highest priority first):
 * 1. argument: tokens=<pgnfw_xxx>[@slot],<pgnfw_yyy>
 *    (module arguments in Surge / Loon / Stash)
 * 2. Persistent storage key "Po0fw_tokens"
 *    (for clients such as Quantumult X that do not support arguments;
 *     the value can be written using BoxJs or a one-time script)
 * 3. INLINE_TOKENS below
 *    (fill this in directly when maintaining a custom copy of the script)
 */

var INLINE_TOKENS = "";

var API_BASE = "https://124.221.69.228/api/firewall/"; // + <token> + "/add"
var STORE_PREFIX = "Po0_fw_";
var TOKENS_KEY = "Po0fw_tokens";
var HIST_WINDOW_MS = 24 * 3600 * 1000; // 🛰️ Cellular activity tracking window

/* ---------- Runtime Compatibility Layer ---------- */

var isQX = typeof $task !== "undefined";
var isSurgeLike = typeof $httpClient !== "undefined"; // Surge / Stash / Shadowrocket / Loon

function storeRead(key) {
  if (isQX) return $prefs.valueForKey(key);
  if (typeof $persistentStore !== "undefined") return $persistentStore.read(key);
  return null;
}

function storeWrite(value, key) {
  if (isQX) return $prefs.setValueForKey(value, key);
  if (typeof $persistentStore !== "undefined") return $persistentStore.write(value, key);
  return false;
}

function notify(title, subtitle, body) {
  if (isQX) $notify(title, subtitle, body);
  else if (typeof $notification !== "undefined") $notification.post(title, subtitle, body);
}

function httpRequest(method, opts) {
  return new Promise(function (resolve) {
    if (isQX) {
      opts.method = method;
      $task.fetch(opts).then(
        function (resp) {
          resolve({ body: resp.body, status: resp.statusCode });
        },
        function (err) {
          resolve({ error: String((err && err.error) || err) });
        }
      );
    } else if (isSurgeLike) {
      var fn = method === "POST" ? $httpClient.post : $httpClient.get;
      fn(opts, function (error, response, body) {
        if (error) resolve({ error: String(error) });
        else resolve({ body: body, status: response && (response.status || response.statusCode) });
      });
    } else {
      resolve({ error: "Unsupported client" });
    }
  });
}

function getArgumentTokens() {
  if (typeof $argument === "undefined" || $argument === null) return "";

  // Loon plugins may inject arguments as an object: {tokens: "..."}
  if (typeof $argument === "object") return String($argument.tokens || "");

  if (typeof $argument === "string" && $argument.length > 0) {
    // Some clients, such as Shadowrocket, may preserve the surrounding quotes
    // from the configuration. Strip them before parsing.
    if (/^["'].*["']$/.test($argument)) $argument = $argument.slice(1, -1);

    // Loon may also inject arguments as a JSON string.
    if ($argument.charAt(0) === "{") {
      try {
        return String(JSON.parse($argument).tokens || "");
      } catch (e) {}
    }

    // Surge / Stash style: tokens=xxx&...
    var pairs = $argument.split("&");
    for (var i = 0; i < pairs.length; i++) {
      var idx = pairs[i].indexOf("=");
      if (idx > 0 && pairs[i].slice(0, idx) === "tokens") {
        return decodeURIComponent(pairs[i].slice(idx + 1));
      }
    }

    // Fallback: treat the entire argument as a token
    // (e.g. Loon argument="pgnfw_...").
    if ($argument.indexOf("pgnfw_") === 0) return $argument;
  }

  return "";
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

// The server registers IPs at the /24 subnet level.
// Entries may be exact IP addresses or x.x.x.0/24 subnets.
//
// If either address is a /24 subnet, compare the first three octets.
// If both are exact IP addresses, require an exact match.
function sameC24(a, b) {
  if (!a || !b) return false;

  a = String(a);
  b = String(b);

  if (a === b) return true;
  if (a.slice(-3) !== "/24" && b.slice(-3) !== "/24") return false;

  var pa = a.replace("/24", "").split(".");
  var pb = b.replace("/24", "").split(".");

  return (
    pa.length === 4 && pb.length === 4 &&
    pa[0] === pb[0] &&
    pa[1] === pb[1] &&
    pa[2] === pb[2]
  );
}

function readHistory(key) {
  try {
    var h = JSON.parse(storeRead(key) || "[]");
    var cutoff = Date.now() - HIST_WINDOW_MS;

    return h.filter(function (e) {
      return e.ts > cutoff;
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

  return httpRequest("POST", {
    url: url,
    headers: { "Content-Type": "application/json" },
    body: "",
    timeout: 15,
  }).then(function (r) {
    if (r.error) return { error: r.error };

    var data = null;
    try {
      data = JSON.parse(r.body);
    } catch (e) {}

    // When registering a pinned slot, HTTP 403 indicates that the current IP
    // is already assigned to a different slot. Remove the existing assignment
    // through the web UI before retrying.
    if (r.status === 403) {
      return {
        error: "Slot conflict: this IP is already assigned to another slot. Remove the existing assignment in the web UI first.",
        conflict: true,
        currentIp: data && data.currentIp,
      };
    }

    if (!data) {
      return { error: "Invalid API response: " + String(r.body).slice(0, 80) };
    }

    // Whitelist entries are objects of the form {ip, slot}
    // (older versions returned plain IP strings).
    // Build an IP-to-slot mapping, then flatten the whitelist into an IP array.
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

  var ctx = {
    kvState: kvState,
    kvHist: kvHist,
    slot: item.slot,
  };

  // The server handles duplicate IPs idempotently, so simply call /add
  // without checking the existing whitelist first.
  return apiCall(item.token, item.slot).then(function (st) {
    if (st.applied) {
      var hist = readHistory(kvHist);
      var last = hist.length ? hist[hist.length - 1] : null;

      if (!last || last.ip !== st.currentIp) {
        hist.push({
          ip: st.currentIp,
          src: cellular ? "cell" : "fixed",
          ts: Date.now(),
        });

        storeWrite(JSON.stringify(hist.slice(-10)), kvHist);
      }
    }

    ctx.st = st;
    return ctx;
  });
}

// One entry per token. Stored information excludes the token itself and
// contains only whitelist and slot details. Cellular IPs are marked with 🛰️.
function describe(index, ctx) {
  var st = ctx.st;
  var pin = ctx.slot !== null && ctx.slot !== undefined && ctx.slot !== ""
    ? " ⛰️" + ctx.slot
    : "";

  var head = "#" + (index + 1) + pin + " ";

  if (st.error) return head + "🗻 " + st.error;
  if (st.enabled === false) return head + "⚠️ Firewall is disabled";

  if (!st.applied) {
    return head + "🗻 Whitelisting failed " + st.whitelist.length + "/" + st.limit;
  }

  var hist = readHistory(ctx.kvHist);
  var cellIps = {};

  hist.forEach(function (e) {
    if (e.src === "cell") cellIps[e.ip] = true;
  });

  var slotOf = st.slotOf || {};

  var ips = st.whitelist
    .map(function (ip) {
      var slotTag = slotOf[ip] !== undefined ? " ⛰️" + slotOf[ip] : "";

      return (
        ip +
        slotTag +
        (cellIps[ip] ? " 🛰️" : "") +
        (sameC24(ip, st.currentIp) ? " ←" : "")
      );
    })
    .join("\n    ");

  return head + "🌋 " + st.whitelist.length + "/" + st.limit + "\n    " + ips;
}

// Token separators: , | ; 、； and whitespace.
// Segments that do not start with pgnfw_ (such as placeholder text)
// are ignored.
//
// Each token may optionally include an @slot suffix:
//   pgnfw_xxx@0  -> pin to slot 0
//   pgnfw_xxx    -> use a slotless entry
var tokens = (getArgumentTokens() || storeRead(TOKENS_KEY) || INLINE_TOKENS || "")
  .split(/[,|;、\s]+/)
  .map(function (s) {
    return s.trim();
  })
  .filter(function (s) {
    return s.indexOf("pgnfw_") === 0;
  })
  .map(function (s) {
    var at = s.indexOf("@");

    if (at === -1) return { token: s, slot: null };

    var n = parseInt(s.slice(at + 1), 10);

    return {
      token: s.slice(0, at),
      slot: isNaN(n) ? null : n,
    };
  });

if (tokens.length === 0) {
  notify(
    "Po0 Firewall Whitelist",
    "No token configured",
    "Configure a pgnfw_ token using one of these options: module argument 'tokens', persistent storage key 'Po0fw_tokens', or the INLINE_TOKENS constant in the script."
  );

  finish(
    "Po0 Whitelist: No Token Configured",
    "Please provide a pgnfw_ token. Separate multiple tokens with |.",
    false
  );
} else {
  Promise.all(
    tokens.map(function (t, i) {
      return ensureWhitelisted(t, i);
    })
  ).then(function (results) {
    var okCount = 0;
    var exitIp = "?";
    var lines = [];
    var changed = false;

    for (var i = 0; i < results.length; i++) {
      var st = results[i].st;

      if (st.applied) okCount++;
      if (st.currentIp) exitIp = st.currentIp;

      lines.push(describe(i, results[i]));

      var state = (st.currentIp || "?") + "|" + (st.applied ? "1" : "0");

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

    // Send a notification only when the exit IP or whitelist status changes.
    // Routine POST requests remain silent.
    if (changed) {
      notify("Po0 Firewall Whitelist", title, content);
    }

    finish(title, content, allOk);
  });
}
