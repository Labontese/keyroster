// keyroster-server's one script: the passkey registration ceremony of the
// invite page (02-08). Plain ES2017, no modules, no third-party code. It
// reads the begin and finish URLs from the data- attributes of
// #kr-enroll, runs navigator.credentials.create, and shows the
// fingerprint the server computed. Every text it shows is set with
// textContent, never as markup.
(function () {
  "use strict";

  function b64urlToBytes(s) {
    var b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) {
      b64 += "=";
    }
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  function bytesToB64url(buf) {
    var bytes = new Uint8Array(buf);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // postJSON posts body (or nothing) to url and returns the decoded
  // answer. A non-2xx answer throws with the server's error text.
  async function postJSON(url, body) {
    var init = {
      method: "POST",
      credentials: "same-origin",
      headers: { "Accept": "application/json" }
    };
    if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    var resp = await fetch(url, init);
    var data = null;
    try {
      data = await resp.json();
    } catch (e) {
      data = null;
    }
    if (!resp.ok) {
      var err = new Error(data && typeof data.error === "string" ? data.error : "the server answered " + resp.status);
      err.fromServer = true;
      throw err;
    }
    return data;
  }

  function creationOptions(begin) {
    var pk = begin.publicKey;
    pk.challenge = b64urlToBytes(pk.challenge);
    pk.user.id = b64urlToBytes(pk.user.id);
    if (Array.isArray(pk.excludeCredentials)) {
      pk.excludeCredentials = pk.excludeCredentials.map(function (c) {
        var d = { type: c.type, id: b64urlToBytes(c.id) };
        if (Array.isArray(c.transports)) {
          d.transports = c.transports;
        }
        return d;
      });
    }
    return pk;
  }

  function finishBody(cred) {
    var r = cred.response;
    var transports = typeof r.getTransports === "function" ? r.getTransports() : [];
    var body = {
      id: cred.id,
      rawId: bytesToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bytesToB64url(r.clientDataJSON),
        attestationObject: bytesToB64url(r.attestationObject),
        transports: transports
      },
      clientExtensionResults: typeof cred.getClientExtensionResults === "function" ? cred.getClientExtensionResults() : {}
    };
    if (cred.authenticatorAttachment) {
      body.authenticatorAttachment = cred.authenticatorAttachment;
    }
    return body;
  }

  function start() {
    var root = document.getElementById("kr-enroll");
    if (!root) {
      return;
    }
    var button = document.getElementById("kr-register");
    var alertEl = document.getElementById("kr-error");
    var result = document.getElementById("kr-result");
    var fingerprint = document.getElementById("kr-fingerprint");
    var details = document.getElementById("kr-details");
    var beginURL = root.getAttribute("data-begin");
    var finishURL = root.getAttribute("data-finish");

    if (!window.PublicKeyCredential || !navigator.credentials || typeof navigator.credentials.create !== "function") {
      alertEl.textContent = "This browser does not support passkeys";
      button.disabled = true;
      return;
    }

    button.addEventListener("click", async function () {
      button.disabled = true;
      alertEl.textContent = "";
      try {
        var begin = await postJSON(beginURL);
        var cred = await navigator.credentials.create({ publicKey: creationOptions(begin) });
        if (!cred) {
          throw new Error("no passkey was created");
        }
        var done = await postJSON(finishURL, finishBody(cred));
        fingerprint.textContent = String(done.fingerprint);
        details.textContent = "Algorithm " + String(done.algorithm) + "; " + (done.synced ? "synced passkey" : "not synced");
        result.hidden = false;
        button.hidden = true;
      } catch (e) {
        if (e && e.fromServer) {
          alertEl.textContent = e.message;
        } else if (e) {
          alertEl.textContent = String(e.name) + ": " + String(e.message);
        } else {
          alertEl.textContent = "Registration failed";
        }
        button.disabled = false;
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
