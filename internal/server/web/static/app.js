// keyroster-server's one script: the passkey registration ceremony of the
// invite page (02-08) and the passkey sign-in ceremony of the login page
// (02-10). Plain ES2017, no modules, no third-party code. Each reads its
// begin and finish URLs from the data- attributes of its section
// (#kr-enroll, #kr-login): registration runs navigator.credentials.create
// and shows the fingerprint the server computed, sign-in runs
// navigator.credentials.get and goes to the account page. Every text it
// shows is set with textContent, never as markup.
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

  // showError writes the failure e into the alert element as text: the
  // server's error text, or else the exception's name and message.
  function showError(alertEl, e, fallback) {
    if (e && e.fromServer) {
      alertEl.textContent = e.message;
    } else if (e) {
      alertEl.textContent = String(e.name) + ": " + String(e.message);
    } else {
      alertEl.textContent = fallback;
    }
  }

  function startEnroll() {
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
        showError(alertEl, e, "Registration failed");
        button.disabled = false;
      }
    });
  }

  function requestOptions(begin) {
    var pk = begin.publicKey;
    var opts = {
      challenge: b64urlToBytes(pk.challenge),
      rpId: pk.rpId,
      userVerification: pk.userVerification,
      timeout: pk.timeout,
      allowCredentials: []
    };
    if (Array.isArray(pk.allowCredentials)) {
      opts.allowCredentials = pk.allowCredentials.map(function (c) {
        return { type: c.type, id: b64urlToBytes(c.id) };
      });
    }
    return opts;
  }

  function assertionBody(challengeID, cred) {
    var r = cred.response;
    return {
      challenge_id: challengeID,
      credential_id: bytesToB64url(cred.rawId),
      authenticator_data: bytesToB64url(r.authenticatorData),
      client_data_json: bytesToB64url(r.clientDataJSON),
      signature: bytesToB64url(r.signature)
    };
  }

  // startLogin wires the sign-in form of #kr-login: begin with the user
  // name, navigator.credentials.get over the server's challenge and the
  // user's bound credentials, finish, then the account page.
  function startLogin() {
    var root = document.getElementById("kr-login");
    if (!root) {
      return;
    }
    var form = document.getElementById("kr-login-form");
    var input = document.getElementById("kr-user");
    var button = document.getElementById("kr-signin");
    var alertEl = document.getElementById("kr-error");
    var beginURL = root.getAttribute("data-begin");
    var finishURL = root.getAttribute("data-finish");

    if (!window.PublicKeyCredential || !navigator.credentials || typeof navigator.credentials.get !== "function") {
      alertEl.textContent = "This browser does not support passkeys";
      button.disabled = true;
      return;
    }

    form.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      button.disabled = true;
      alertEl.textContent = "";
      try {
        var begin = await postJSON(beginURL, { user: input.value });
        var cred = await navigator.credentials.get({ publicKey: requestOptions(begin) });
        if (!cred) {
          throw new Error("no passkey was used");
        }
        var done = await postJSON(finishURL, assertionBody(begin.challenge_id, cred));
        var next = typeof done.redirect === "string" && done.redirect.charAt(0) === "/" && done.redirect.charAt(1) !== "/" ? done.redirect : "/account";
        location.assign(next);
      } catch (e) {
        showError(alertEl, e, "Sign-in failed");
        button.disabled = false;
      }
    });
  }

  function start() {
    startEnroll();
    startLogin();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
