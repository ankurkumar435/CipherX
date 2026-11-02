(() => {
  const NAME_RE = /^[A-Za-z0-9_]{3,20}$/;
  const $ = (id) => document.getElementById(id);

  const authView = $("auth");
  const appView = $("app");
  const statusEl = $("auth-status");
  const confirmWrap = $("confirm-wrap");
  const userList = $("user-list");
  const messagesEl = $("messages");
  const contactSearch = $("contact-search");
  const chatSearch = $("chat-search");
  const chatSearchStatus = $("chat-search-status");
  const clearChatSearch = $("clear-chat-search");
  const toggleChatSearch = $("toggle-chat-search");
  const typingStatus = $("typing-status");
  const draft = $("draft");
  const sendBtn = $("send");
  const emojiToggle = $("emoji-toggle");
  const emojiPicker = $("emoji-picker");
  const peerNameEl = $("peer-name");
  const peerAvatarEl = $("peer-avatar");
  const peerStatusEl = $("peer-status");
  const backToContacts = $("back-to-contacts");
  const appRoot = $("app");
  const meAvatarEl = $("me-avatar");
  const EMOJIS = ["😀", "😂", "😊", "😍", "🥰", "😉", "😎", "😭", "😡", "👍", "👎", "👏", "🙏", "❤️", "💔", "🔥", "🎉", "✨", "💯", "🤝", "🤔", "😴", "✅", "👋"];

  let mode = "login";
  let ws = null;
  let me = null;
  let myName = "";
  let activePeer = null;
  let online = [];
  let registered = [];
  let profiles = {};
  const chats = {};
  const pendingOut = {};
  const pendingIn = {};
  const unreadCounts = {};
  const remoteTypingTimers = {};
  let localTypingPeer = null;
  let localTypingTimer = null;
  let localTypingHeartbeat = null;

  function setStatus(text, ok) {
    statusEl.textContent = text || "";
    statusEl.style.color = ok ? "var(--accent)" : "var(--danger)";
  }

  function hasSecureCrypto() {
    return Boolean(
      window.isSecureContext &&
      window.crypto &&
      window.crypto.subtle &&
      typeof window.crypto.subtle.importKey === "function"
    );
  }

  function secureCryptoMessage() {
    return "Secure encryption is unavailable. Open this site over HTTPS with a certificate trusted by this device.";
  }

  function setMode(next) {
    mode = next;
    $("tab-login").classList.toggle("active", mode === "login");
    $("tab-register").classList.toggle("active", mode === "register");
    const registering = mode === "register";
    confirmWrap.classList.toggle("hidden", !registering);
    $("confirm").disabled = !registering;
    $("confirm").required = registering;
    $("password").autocomplete = registering ? "new-password" : "current-password";
    $("auth-submit").textContent = registering ? "Create account" : "Login";
    setStatus("");
  }

  $("tab-login").onclick = () => setMode("login");
  $("tab-register").onclick = () => setMode("register");

  function openSocket() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    return new WebSocket(`${proto}://${location.host}/ws`);
  }

  function waitMessage(socket) {
    return new Promise((resolve, reject) => {
      const onMsg = (ev) => {
        cleanup();
        try {
          resolve(JSON.parse(ev.data));
        } catch (err) {
          reject(err);
        }
      };
      const onErr = () => {
        cleanup();
        reject(new Error("connection failed"));
      };
      const onClose = () => {
        cleanup();
        reject(new Error("disconnected"));
      };
      function cleanup() {
        socket.removeEventListener("message", onMsg);
        socket.removeEventListener("error", onErr);
        socket.removeEventListener("close", onClose);
      }
      socket.addEventListener("message", onMsg);
      socket.addEventListener("error", onErr);
      socket.addEventListener("close", onClose);
    });
  }

  function sendJson(socket, obj) {
    socket.send(JSON.stringify(obj));
  }

  function setAvatar(element, name) {
    let hash = 0;
    for (const char of name) hash = (hash * 31 + char.codePointAt(0)) | 0;
    const parts = name.split(/[_\s-]+/).filter(Boolean);
    const initials = parts.length > 1
      ? parts.slice(0, 2).map((part) => Array.from(part)[0]).join("")
      : Array.from(name).slice(0, 2).join("");
    element.textContent = initials.toLocaleUpperCase();
    element.style.setProperty("--avatar-hue", String((Math.abs(hash) * 47) % 360));
  }

  function setPeerPresence(name) {
    const isOn = online.includes(name);
    peerStatusEl.replaceChildren();
    const dot = document.createElement("span");
    dot.className = "dot" + (isOn ? " on" : "");
    const label = document.createElement("span");
    label.textContent = isOn ? "Active now" : "Offline";
    peerStatusEl.append(dot, label);
  }

  function stopTyping(peer = localTypingPeer) {
    if (localTypingTimer) {
      clearTimeout(localTypingTimer);
      localTypingTimer = null;
    }
    if (localTypingHeartbeat) {
      clearInterval(localTypingHeartbeat);
      localTypingHeartbeat = null;
    }
    if (peer && localTypingPeer === peer && ws && ws.readyState === WebSocket.OPEN) {
      sendJson(ws, { type: "typing", to: peer, typing: false });
    }
    if (localTypingPeer === peer) localTypingPeer = null;
  }

  function signalTyping() {
    if (!activePeer || !ws || ws.readyState !== WebSocket.OPEN) return;
    if (localTypingPeer !== activePeer) {
      stopTyping();
      localTypingPeer = activePeer;
      sendJson(ws, { type: "typing", to: activePeer, typing: true });
      localTypingHeartbeat = setInterval(() => {
        if (localTypingPeer && ws && ws.readyState === WebSocket.OPEN) {
          sendJson(ws, { type: "typing", to: localTypingPeer, typing: true });
        }
      }, 1200);
    }
    if (localTypingTimer) clearTimeout(localTypingTimer);
    localTypingTimer = setTimeout(() => stopTyping(activePeer), 1600);
  }

  function updateTypingStatus() {
    const timer = remoteTypingTimers[activePeer];
    typingStatus.classList.toggle("hidden", !timer);
  }

  function setRemoteTyping(peer, isTyping) {
    if (remoteTypingTimers[peer]) {
      clearTimeout(remoteTypingTimers[peer]);
      delete remoteTypingTimers[peer];
    }
    if (isTyping) {
      remoteTypingTimers[peer] = setTimeout(() => {
        delete remoteTypingTimers[peer];
        if (peer === activePeer) updateTypingStatus();
      }, 3000);
    }
    if (peer === activePeer) updateTypingStatus();
  }

  async function createAccount(name, password) {
    const socket = openSocket();
    try {
      await new Promise((resolve, reject) => {
        socket.addEventListener("open", resolve, { once: true });
        socket.addEventListener("error", () => reject(new Error("could not reach server")), { once: true });
        socket.addEventListener("close", () => reject(new Error("disconnected")), { once: true });
      });
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const verifier = await SecureMessage.scryptVerifier(password, salt);
      sendJson(socket, {
        action: "register",
        user: name,
        salt: SecureMessage.b64(salt),
        verifier: SecureMessage.b64(verifier),
      });
      const reply = await waitMessage(socket);
      if (reply.type !== "ok") throw new Error(reply.msg || "registration failed");
    } finally {
      socket.close();
    }
  }

  function getProfileName(name) {
    const profile = profiles[name];
    return profile
      ? `${profile.first_name || ""} ${profile.last_name || ""}`.trim() || name
      : name;
  }

  function matchesContact(name, query) {
    return `${name} ${getProfileName(name)}`.toLocaleLowerCase().includes(query);
  }

  async function login(name, password) {
    const socket = openSocket();
    await new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", () => reject(new Error("could not reach server")), { once: true });
    });
    sendJson(socket, { action: "login", user: name });
    const challenge = await waitMessage(socket);
    if (challenge.type !== "challenge") {
      socket.close();
      throw new Error(challenge.msg || "login failed");
    }
    setStatus("Proving password without sending it…", true);
    const key = await SecureMessage.scryptVerifier(password, SecureMessage.unb64(challenge.salt));
    const proof = await SecureMessage.hmacSha256(key, SecureMessage.unb64(challenge.nonce));
    sendJson(socket, { proof: SecureMessage.b64(proof) });
    const reply = await waitMessage(socket);
    if (reply.type !== "ok") {
      socket.close();
      throw new Error(reply.msg || "login failed");
    }
    return {
      socket,
      roster: {
        online: reply.online || [],
        all: reply.all || [],
        profiles: reply.profiles || {},
      },
    };
  }

  function ensureChat(peer) {
    if (!chats[peer]) chats[peer] = [];
    return chats[peer];
  }

  function pushMsg(peer, entry) {
    ensureChat(peer).push(entry);
    if (peer === activePeer) renderMessages();
  }

  function renderUsers() {
    const names = [...new Set([...registered, ...online])].filter((n) => n !== myName).sort();
    const query = contactSearch.value.trim().toLocaleLowerCase();
    const visibleNames = names.filter((name) => matchesContact(name, query));
    userList.innerHTML = "";
    if (!visibleNames.length) {
      const empty = document.createElement("li");
      const emptyButton = document.createElement("button");
      emptyButton.type = "button";
      emptyButton.disabled = true;
      emptyButton.textContent = names.length ? "No people match your search" : "No other accounts yet";
      empty.appendChild(emptyButton);
      userList.appendChild(empty);
      return;
    }
    for (const name of visibleNames) {
      const li = document.createElement("li");
      if (name === activePeer) li.classList.add("active");
      const btn = document.createElement("button");
      btn.type = "button";
      const isOn = online.includes(name);
      const avatar = document.createElement("span");
      avatar.className = "avatar contact-avatar";
      avatar.setAttribute("aria-hidden", "true");
      setAvatar(avatar, name);
      const details = document.createElement("span");
      details.className = "contact-details";
      const label = document.createElement("span");
      label.className = "contact-name";
      label.textContent = getProfileName(name);
      const state = document.createElement("span");
      state.className = "presence-label";
      const dot = document.createElement("span");
      dot.className = "dot" + (isOn ? " on" : "");
      dot.title = isOn ? "online" : "offline";
      const stateText = document.createElement("span");
      stateText.textContent = isOn ? "Active now" : "Offline";
      state.append(dot, stateText);
      details.append(label, state);
      const trailing = document.createElement("span");
      trailing.className = "user-trailing";
      const unread = unreadCounts[name] || 0;
      if (unread > 0) {
        const badge = document.createElement("span");
        badge.className = "unread-count";
        badge.textContent = unread > 99 ? "99+" : String(unread);
        badge.title = `${unread} unread message${unread === 1 ? "" : "s"}`;
        badge.setAttribute("aria-label", badge.title);
        trailing.appendChild(badge);
      }
      const onlineDot = document.createElement("span");
      onlineDot.className = "online-dot" + (isOn ? " on" : "");
      onlineDot.title = isOn ? "online" : "offline";
      trailing.prepend(onlineDot);
      btn.setAttribute(
        "aria-label",
        `${getProfileName(name)} (${name}), ${isOn ? "online" : "offline"}${unread > 0 ? `, ${unread} unread message${unread === 1 ? "" : "s"}` : ""}`
      );
      btn.append(avatar, details, trailing);
      btn.onclick = () => selectPeer(name);
      li.appendChild(btn);
      userList.appendChild(li);
    }
  }

  function renderMessages() {
    messagesEl.innerHTML = "";
    const items = ensureChat(activePeer || "");
    if (!activePeer) {
      chatSearchStatus.textContent = "";
      const el = document.createElement("div");
      el.className = "bubble sys";
      el.textContent = "Choose a person on the left. Messages are encrypted on this device.";
      messagesEl.appendChild(el);
      return;
    }
    const query = chatSearch.value.trim().toLocaleLowerCase();
    const visibleItems = query
      ? items.filter((item) => String(item.text).toLocaleLowerCase().includes(query))
      : items;
    chatSearchStatus.textContent = query
      ? `${visibleItems.length} matching message${visibleItems.length === 1 ? "" : "s"}`
      : "";
    clearChatSearch.classList.toggle("hidden", !query);
    if (query && visibleItems.length === 0) {
      const empty = document.createElement("div");
      empty.className = "bubble sys";
      empty.textContent = "No messages match your search.";
      messagesEl.appendChild(empty);
    }
    for (const item of visibleItems) {
      const el = document.createElement("div");
      el.className = "bubble " + item.kind + (item.bad ? " bad" : "");
      el.textContent = item.text;
      messagesEl.appendChild(el);
    }
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function selectPeer(name) {
    activePeer = name;
    appRoot.classList.add("mobile-chat-open");
    unreadCounts[name] = 0;
    chatSearch.value = "";
    chatSearch.disabled = true;
    clearChatSearch.disabled = true;
    clearChatSearch.classList.add("hidden");
    toggleChatSearch.disabled = false;
    $("chat-search-control").classList.remove("search-open");
    toggleChatSearch.setAttribute("aria-expanded", "false");
    peerNameEl.textContent = getProfileName(name);
    setAvatar(peerAvatarEl, getProfileName(name));
    peerAvatarEl.classList.remove("hidden");
    peerStatusEl.classList.remove("hidden");
    setPeerPresence(name);
    updateTypingStatus();
    draft.disabled = !online.includes(name);
    sendBtn.disabled = draft.disabled;
    emojiToggle.disabled = draft.disabled;
    stopTyping();
    emojiPicker.classList.add("hidden");
    emojiToggle.setAttribute("aria-expanded", "false");
    renderUsers();
    renderMessages();
    if (online.includes(name) && !me.session[name]) {
      sendJson(ws, { type: "get_bundle", user: name });
    }
  }

  backToContacts.addEventListener("click", () => {
    appRoot.classList.remove("mobile-chat-open");
  });

  async function deliver(packet) {
    let sender;
    try {
      sender = JSON.parse(new TextDecoder().decode(SecureMessage.unb64(packet.header))).from;
    } catch (e) {
      if (activePeer) pushMsg(activePeer, { kind: "sys bad", text: "REJECTED: malformed message (tampered)", bad: true });
      return;
    }
    try {
      const text = await me.receive(packet);
      pushMsg(sender, { kind: "them", text });
      if (sender !== activePeer || document.visibilityState !== "visible") {
        unreadCounts[sender] = (unreadCounts[sender] || 0) + 1;
        renderUsers();
      }
    } catch (e) {
      pushMsg(sender, { kind: "sys bad", text: String(e.message || e), bad: true });
    }
  }

  async function onServerMessage(m) {
    if (m.type === "users") {
      online = m.online || [];
      registered = m.all || [];
      profiles = m.profiles || profiles;
      renderUsers();
      if (activePeer) setPeerPresence(activePeer);
      if (activePeer) {
        draft.disabled = !online.includes(activePeer);
        sendBtn.disabled = draft.disabled;
        emojiToggle.disabled = draft.disabled;
        if (!online.includes(activePeer)) setRemoteTyping(activePeer, false);
      }
    } else if (m.type === "typing") {
      if (typeof m.from === "string" && m.from !== myName && typeof m.typing === "boolean") {
        setRemoteTyping(m.from, m.typing);
      }
    } else if (m.type === "bundle") {
      const bundle = m.bundle;
      const peer = bundle.name;
      try {
        await me.keyExchange(bundle);
        pushMsg(peer, {
          kind: "sys",
          text: "Secure session with " + getProfileName(peer) + ".",
        });
        for (const text of pendingOut[peer] || []) {
          sendJson(ws, { type: "msg", to: peer, packet: await me.send(peer, text) });
        }
        pendingOut[peer] = [];
        for (const pkt of pendingIn[peer] || []) await deliver(pkt);
        pendingIn[peer] = [];
      } catch (e) {
        pushMsg(peer, { kind: "sys bad", text: String(e.message || e), bad: true });
      }
    } else if (m.type === "msg") {
      const pkt = m.packet;
      let sender;
      try {
        sender = JSON.parse(new TextDecoder().decode(SecureMessage.unb64(pkt.header))).from;
      } catch (e) {
        pushMsg(activePeer || myName, { kind: "sys bad", text: "REJECTED: malformed message (tampered)", bad: true });
        return;
      }
      if (me.session[sender]) await deliver(pkt);
      else {
        pendingIn[sender] = pendingIn[sender] || [];
        pendingIn[sender].push(pkt);
        sendJson(ws, { type: "get_bundle", user: sender });
      }
    } else if (m.type === "error") {
      if (activePeer) pushMsg(activePeer, { kind: "sys bad", text: m.msg, bad: true });
      else setStatus(m.msg);
    }
  }

  function enterChat(name, socket) {
    ws = socket;
    myName = name;
    me = new SecureMessage.User(name);
    $("me-name").textContent = getProfileName(name);
    $("me-username").textContent = name;
    setAvatar(meAvatarEl, getProfileName(name));
    authView.classList.add("hidden");
    appView.classList.remove("hidden");
    renderUsers();
    sendJson(ws, { type: "publish", bundle: me.publicBundle() });
    sendJson(ws, { type: "users" });
    ws.addEventListener("message", (ev) => {
      try {
        onServerMessage(JSON.parse(ev.data));
      } catch (e) {
        /* ignore */
      }
    });
    ws.addEventListener("close", () => {
      draft.disabled = true;
      sendBtn.disabled = true;
      emojiToggle.disabled = true;
      stopTyping();
      for (const peer of Object.keys(remoteTypingTimers)) setRemoteTyping(peer, false);
      $("me-status").replaceChildren();
      const dot = document.createElement("span");
      dot.className = "dot";
      $("me-status").append(dot, document.createTextNode("Offline"));
      pushMsg(activePeer || name, { kind: "sys bad", text: "Disconnected from server.", bad: true });
    });
  }

  $("auth-submit").addEventListener("click", async () => {
    if (!hasSecureCrypto()) {
      setStatus(secureCryptoMessage());
      return;
    }
    const name = $("username").value.trim();
    const password = $("password").value;
    const confirm = $("confirm").value;
    if (!NAME_RE.test(name)) {
      setStatus("Username must be 3–20 letters, digits, or underscore.");
      return;
    }
    if (password.length < 6) {
      setStatus("Password must be at least 6 characters.");
      return;
    }
    if (mode === "register") {
      if (password !== confirm) {
        setStatus("Passwords do not match.");
        return;
      }
    }
    $("auth-submit").disabled = true;
    try {
      if (mode === "register") {
        await createAccount(name, password);
        setMode("login");
        setStatus("Account created. Logging in…", true);
      }
      const { socket, roster } = await login(name, password);
      online = roster.online;
      registered = roster.all;
      profiles = roster.profiles || {};
      enterChat(name, socket);
    } catch (e) {
      setStatus(e.message || String(e));
    } finally {
      $("auth-submit").disabled = !hasSecureCrypto();
    }
  });

  $("auth-form").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && event.target instanceof HTMLInputElement) {
      event.preventDefault();
      if (!$("auth-submit").disabled) $("auth-submit").click();
    }
  });

  $("composer").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const text = draft.value;
    if (!text.trim() || !activePeer || !ws) return;
    draft.value = "";
    stopTyping(activePeer);
    pushMsg(activePeer, { kind: "me", text });
    try {
      if (me.session[activePeer]) {
        sendJson(ws, { type: "msg", to: activePeer, packet: await me.send(activePeer, text) });
      } else {
        pendingOut[activePeer] = pendingOut[activePeer] || [];
        pendingOut[activePeer].push(text);
        sendJson(ws, { type: "get_bundle", user: activePeer });
      }
    } catch (e) {
      pushMsg(activePeer, { kind: "sys bad", text: String(e.message || e), bad: true });
    }
  });

  contactSearch.addEventListener("input", renderUsers);

  chatSearch.addEventListener("input", () => {
    clearChatSearch.disabled = !chatSearch.value;
    renderMessages();
  });

  clearChatSearch.addEventListener("click", () => {
    chatSearch.value = "";
    clearChatSearch.disabled = true;
    clearChatSearch.classList.add("hidden");
    renderMessages();
    toggleChatSearch.focus();
  });

  toggleChatSearch.addEventListener("click", () => {
    const isOpen = toggleChatSearch.getAttribute("aria-expanded") !== "true";
    toggleChatSearch.setAttribute("aria-expanded", String(isOpen));
    $("chat-search-control").classList.toggle("search-open", isOpen);
    chatSearch.disabled = !isOpen;
    if (isOpen) chatSearch.focus();
    else {
      chatSearch.value = "";
      clearChatSearch.disabled = true;
      clearChatSearch.classList.add("hidden");
      renderMessages();
    }
  });

  document.addEventListener("click", (event) => {
    if (
      toggleChatSearch.getAttribute("aria-expanded") === "true" &&
      !event.target.closest("#chat-search-control")
    ) {
      $("chat-search-control").classList.remove("search-open");
      toggleChatSearch.setAttribute("aria-expanded", "false");
      chatSearch.disabled = true;
      chatSearch.value = "";
      clearChatSearch.disabled = true;
      clearChatSearch.classList.add("hidden");
      renderMessages();
    }
  });

  draft.addEventListener("input", () => {
    if (draft.value.trim()) signalTyping();
    else stopTyping(activePeer);
  });

  for (const emoji of EMOJIS) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "emoji-option";
    button.textContent = emoji;
    button.setAttribute("aria-label", emoji);
    button.title = emoji;
    button.addEventListener("click", () => {
      const start = draft.selectionStart;
      const end = draft.selectionEnd;
      draft.setRangeText(emoji, start, end, "end");
      draft.focus();
      draft.dispatchEvent(new Event("input", { bubbles: true }));
      emojiPicker.classList.add("hidden");
      emojiToggle.setAttribute("aria-expanded", "false");
    });
    emojiPicker.appendChild(button);
  }

  emojiToggle.addEventListener("click", () => {
    const isOpen = emojiPicker.classList.toggle("hidden") === false;
    emojiToggle.setAttribute("aria-expanded", String(isOpen));
    if (isOpen) emojiPicker.querySelector("button")?.focus();
  });

  document.addEventListener("click", (event) => {
    if (!emojiPicker.contains(event.target) && event.target !== emojiToggle) {
      emojiPicker.classList.add("hidden");
      emojiToggle.setAttribute("aria-expanded", "false");
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && toggleChatSearch.getAttribute("aria-expanded") === "true") {
      $("chat-search-control").classList.remove("search-open");
      toggleChatSearch.setAttribute("aria-expanded", "false");
      chatSearch.disabled = true;
      chatSearch.value = "";
      clearChatSearch.disabled = true;
      clearChatSearch.classList.add("hidden");
      renderMessages();
      toggleChatSearch.focus();
    }
    if (event.key === "Escape" && !emojiPicker.classList.contains("hidden")) {
      emojiPicker.classList.add("hidden");
      emojiToggle.setAttribute("aria-expanded", "false");
      emojiToggle.focus();
    }
  });

  draft.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && !ev.shiftKey) {
      ev.preventDefault();
      $("composer").requestSubmit();
    }
  });

  $("logout").onclick = () => {
    if (ws) ws.close();
    location.reload();
  };

  window.addEventListener("blur", () => stopTyping());

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && activePeer && unreadCounts[activePeer]) {
      unreadCounts[activePeer] = 0;
      renderUsers();
    }
  });

  window.addEventListener("resize", () => {
    if (window.visualViewport) {
      document.documentElement.style.setProperty("--viewport-height", `${window.visualViewport.height}px`);
    }
  });

  setMode("login");
  $("auth-submit").disabled = !hasSecureCrypto();
  if (!hasSecureCrypto()) setStatus(secureCryptoMessage());
})();
