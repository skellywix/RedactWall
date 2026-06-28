/*
 * PromptWall site adapters + safety helpers (browser-safe, zero deps).
 * Shared by the content script and the background worker. Pure functions only
 * (no DOM), so they are unit-testable in Node and identical on every sensor.
 *
 * Exposed as CommonJS (Node) and window/self.PSAdapters (browser/worker).
 */
(function (root) {
  'use strict';

  // Per-site "Send" button selectors, tried in order. The reliable way to
  // resume a send after the user approves is to click the site's REAL button
  // (its onClick reads the composer), not to re-dispatch a synthetic key event
  // that React ignores (REVIEW #7). Generic fallbacks are appended at use time.
  const SEND_BUTTONS = {
    'chatgpt.com': ['button[data-testid="send-button"]', 'button[aria-label*="Send" i]'],
    'chat.openai.com': ['button[data-testid="send-button"]', 'button[aria-label*="Send" i]'],
    'claude.ai': ['button[aria-label*="Send message" i]', 'button[aria-label*="Send" i]'],
    'gemini.google.com': ['button[aria-label*="Send" i]', 'button.send-button-container button', 'button.send-button'],
    'copilot.microsoft.com': ['button[aria-label*="Submit" i]', 'button[aria-label*="Send" i]'],
    'www.perplexity.ai': ['button[aria-label*="Submit" i]', 'button[aria-label*="Send" i]'],
    'poe.com': ['button[class*="sendButton" i]', 'button[aria-label*="Send" i]'],
    'chat.deepseek.com': ['button[aria-label*="Send" i]', 'button[type="submit"]'],
    'chat.qwen.ai': ['button[aria-label*="Send" i]', 'button[type="submit"]'],
    'kimi.com': ['button[aria-label*="Send" i]', 'button[type="submit"]'],
    'doubao.com': ['button[aria-label*="Send" i]', 'button[type="submit"]'],
  };
  const GENERIC_SEND = ['button[data-testid="send-button"]', 'button[aria-label*="Send" i]', 'button[aria-label*="Submit" i]', 'button[type="submit"]'];

  function sendButtonSelectors(host) {
    const site = SEND_BUTTONS[host] || [];
    return site.concat(GENERIC_SEND.filter((s) => !site.includes(s)));
  }

  // Known consumer AI surfaces — used by the background worker to flag "shadow
  // AI": use of an AI tool that policy does NOT govern (so it would otherwise go
  // unmonitored). Parity with the "shadow AI discovery" competitors advertise.
  const AI_HOSTS = [
    'chatgpt.com', 'chat.openai.com', 'claude.ai', 'gemini.google.com', 'bard.google.com',
    'aistudio.google.com', 'notebooklm.google.com', 'copilot.microsoft.com', 'bing.com',
    'perplexity.ai', 'www.perplexity.ai', 'poe.com',
    'character.ai', 'huggingface.co', 'you.com', 'pi.ai', 'deepseek.com', 'chat.deepseek.com',
    'qwen.ai', 'chat.qwen.ai', 'tongyi.aliyun.com', 'qianwen.aliyun.com', 'kimi.com',
    'moonshot.cn', 'kimi.moonshot.cn', 'doubao.com', 'yuanbao.tencent.com', 'yiyan.baidu.com',
    'ernie.baidu.com', 'chatglm.cn', 'z.ai', 'bigmodel.cn', 'minimax.io', 'hailuoai.com',
    'xinghuo.xfyun.cn', 'spark.xfyun.cn', 'ai.360.com', 'metaso.cn', 'wenxiaobai.com',
    'baichuan-ai.com', 'tiangong.kunlun.com', 'hunyuan.tencent.com', 'mistral.ai', 'chat.mistral.ai', 'lechat.mistral.ai', 'groq.com',
    'meta.ai', 'x.ai', 'grok.com', 'notion.so', 'phind.com', 'chatbot.theb.ai',
    'cohere.com', 'coral.cohere.com', 'replicate.com', 'v0.dev', 'bolt.new', 'lovable.dev', 'cursor.com',
    'windsurf.com', 'replit.com', 'blackbox.ai', 'genspark.ai', 'manus.im', 'monica.im', 'flowith.io',
    'jasper.ai', 'copy.ai', 'writesonic.com',
    'chatsonic.com', 'grammarly.com', 'quillbot.com', 'midjourney.com', 'ideogram.ai',
    'runwayml.com', 'krea.ai', 'elevenlabs.io', 'suno.com', 'udio.com',
  ];

  function normalizeHost(value) {
    const raw = String(value || '').trim().toLowerCase().replace(/\s+/g, '-');
    if (!raw) return 'unknown';
    try {
      const url = raw.includes('://') ? new URL(raw) : new URL('https://' + raw);
      return url.hostname.replace(/^www\./, '');
    } catch (_) {
      return raw.replace(/^www\./, '').split(/[/?#]/)[0] || 'unknown';
    }
  }
  function hostMatches(host, base) {
    const h = normalizeHost(host);
    const b = normalizeHost(base);
    if (!b || b === 'unknown') return false;
    if (b === '*') return true;
    if (b.startsWith('*.')) return h.endsWith('.' + b.slice(2));
    if (b.startsWith('*')) {
      const suffix = b.slice(1).replace(/^\./, '');
      return h === suffix || h.endsWith('.' + suffix);
    }
    return h === b || h.endsWith('.' + b);
  }
  function isGoverned(host, governed) { return (governed || []).some((g) => hostMatches(host, g)); }
  function isAiHost(host) { return AI_HOSTS.some((h) => hostMatches(host, h)); }

  // "Man-in-the-Prompt" defense: a malicious extension/script can splice hidden
  // instructions into the composer using zero-width, bidi-override, or Unicode
  // "tag" characters the user can't see. Detect (and strip) them before send so
  // invisible payloads aren't shipped to the model under the user's identity.
  const ZW = /[​-‍⁠﻿]/g;          // zero-width
  const BIDI = /[‪-‮⁦-⁩]/g;        // bidi overrides
  const TAGS = /[\uDB40][\uDC00-\uDC7F]/g;             // Unicode tag chars (surrogate pair E0000-E007F)
  function scanInjection(text) {
    const t = String(text || '');
    const reasons = [];
    if (ZW.test(t)) reasons.push('zero-width characters');
    if (BIDI.test(t)) reasons.push('bidirectional override characters');
    if (TAGS.test(t)) reasons.push('hidden Unicode tag characters');
    ZW.lastIndex = BIDI.lastIndex = TAGS.lastIndex = 0;
    const stripped = t.replace(ZW, '').replace(BIDI, '').replace(TAGS, '');
    return { suspicious: reasons.length > 0, reasons, stripped };
  }

  const api = { SEND_BUTTONS, GENERIC_SEND, sendButtonSelectors, AI_HOSTS, normalizeHost, isGoverned, isAiHost, hostMatches, scanInjection };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.PSAdapters = api;
})(typeof window !== 'undefined' ? window : (typeof self !== 'undefined' ? self : null));
