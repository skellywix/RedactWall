'use strict';
/**
 * Anthropic Messages API upstream adapter.
 *
 * Demonstrates the provider-translation seam: the gateway speaks OpenAI on the
 * front, this adapter maps to/from Anthropic's /v1/messages shape so one policy
 * governs an Anthropic upstream too. Text extraction reuses the canonical
 * OpenAI-side helpers (the gateway still receives OpenAI-shaped requests).
 */
const canonical = require('../canonical');
const { normalizeGatewayUrl } = require('../config');
const { validateProviderCredentials } = require('../providers');
const { readBoundedText } = require('../../sensors/shared/bounded-response');

const SUPPORTED_REQUEST_FIELDS = new Set([
  'model', 'messages', 'max_tokens', 'max_completion_tokens', 'temperature',
  'top_p', 'stop', 'tools', 'tool_choice', 'parallel_tool_calls', 'stream', 'n',
]);
const MESSAGE_ROLES = new Set(['system', 'user', 'assistant', 'tool']);
const TOOL_NAME = /^[a-zA-Z0-9_-]{1,64}$/;

function unsupported(message) {
  const error = new TypeError(message);
  error.code = 'ANTHROPIC_UNSUPPORTED_REQUEST';
  throw error;
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function textContent(message) {
  const content = message.content;
  if (content == null) return [];
  if (typeof content === 'string') return content ? [{ type: 'text', text: content }] : [];
  if (!Array.isArray(content)) unsupported('Anthropic supports only text message content');
  return content.map((part) => {
    if (!plainRecord(part) || part.type !== 'text' || typeof part.text !== 'string') {
      unsupported('Anthropic supports only OpenAI text content parts');
    }
    return { type: 'text', text: part.text };
  }).filter((part) => part.text);
}

function parsedToolArguments(value) {
  let input = value;
  if (typeof input === 'string') {
    try { input = JSON.parse(input); } catch { unsupported('Anthropic tool arguments must be valid JSON'); }
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    unsupported('Anthropic tool arguments must be a JSON object');
  }
  return input;
}

function assistantBlocks(message) {
  const blocks = textContent(message);
  if (message.tool_calls != null && !Array.isArray(message.tool_calls)) {
    unsupported('Anthropic tool_calls must be an array');
  }
  if (Array.isArray(message.tool_calls)) {
    for (const call of message.tool_calls) {
      const fn = call && call.function;
      if (!call || call.type !== 'function' || !call.id || !fn || !fn.name) {
        unsupported('Anthropic tool calls require id, function name, and arguments');
      }
      blocks.push({
        type: 'tool_use',
        id: String(call.id),
        name: String(fn.name),
        input: parsedToolArguments(fn.arguments == null ? '{}' : fn.arguments),
      });
    }
  }
  return blocks;
}

function messageBlocks(message) {
  if (message.role === 'assistant') return assistantBlocks(message);
  if (message.role === 'tool') {
    if (!message.tool_call_id) unsupported('Anthropic tool results require tool_call_id');
    return [{
      type: 'tool_result',
      tool_use_id: String(message.tool_call_id),
      content: canonical.messageText(message),
    }];
  }
  if (message.role !== 'user') unsupported(`Anthropic does not support ${message.role} messages`);
  return textContent(message);
}

function validateMessages(messages) {
  if (!Array.isArray(messages) || !messages.length) {
    unsupported('Anthropic chat requests require at least one message');
  }
  for (const message of messages) {
    if (!plainRecord(message) || !MESSAGE_ROLES.has(message.role)) {
      unsupported('Anthropic supports system, user, assistant, and tool messages only');
    }
    if (message.name != null || message.function_call != null) {
      unsupported('Anthropic does not support named messages or legacy function_call');
    }
    if (message.role !== 'assistant' && message.tool_calls != null) {
      unsupported('Anthropic tool_calls are valid only on assistant messages');
    }
    if (message.role !== 'tool' && message.tool_call_id != null) {
      unsupported('Anthropic tool_call_id is valid only on tool messages');
    }
    const blocks = message.role === 'system' ? textContent(message) : messageBlocks(message);
    if (!blocks.length) unsupported(`Anthropic ${message.role} messages cannot be empty`);
  }
  return messages;
}

function appendTurn(turns, role, blocks) {
  if (!blocks.length) return;
  const previous = turns[turns.length - 1];
  if (previous && previous.role === role) {
    const existing = typeof previous.content === 'string'
      ? [{ type: 'text', text: previous.content }] : previous.content;
    previous.content = existing.concat(blocks);
    return;
  }
  const pureText = blocks.every((block) => block.type === 'text');
  turns.push({ role, content: pureText ? blocks.map((block) => block.text).join('\n') : blocks });
}

function translatedMessages(messages) {
  validateMessages(messages);
  const turns = [];
  const system = [];
  const pendingTools = new Set();
  let conversationStarted = false;
  for (const message of messages) {
    if (message.role === 'system') {
      if (conversationStarted) unsupported('Anthropic system messages must precede the conversation');
      system.push(...textContent(message).map((block) => block.text));
      continue;
    }
    if (!conversationStarted && message.role !== 'user') {
      unsupported('Anthropic conversations must begin with a user message');
    }
    conversationStarted = true;
    if (pendingTools.size && message.role !== 'tool') {
      unsupported('Anthropic tool results must immediately follow tool calls');
    }
    if (message.role === 'tool') {
      if (!pendingTools.delete(String(message.tool_call_id))) {
        unsupported('Anthropic tool results must match a pending tool call');
      }
    } else if (message.role === 'assistant' && Array.isArray(message.tool_calls)) {
      for (const call of message.tool_calls) {
        if (pendingTools.has(String(call.id))) unsupported('Anthropic tool call ids must be unique');
        pendingTools.add(String(call.id));
      }
    }
    const role = message.role === 'assistant' ? 'assistant' : 'user';
    appendTurn(turns, role, messageBlocks(message));
  }
  if (pendingTools.size) unsupported('Anthropic tool calls require matching tool results');
  return { system: system.join('\n') || undefined, turns };
}

function anthropicTools(tools) {
  if (tools == null) return undefined;
  if (!Array.isArray(tools)) unsupported('Anthropic tools must be an array');
  if (!tools.length) return undefined;
  return tools.map((tool) => {
    const fn = tool && tool.function;
    if (!plainRecord(tool) || tool.type !== 'function' || !plainRecord(fn)
        || typeof fn.name !== 'string' || !TOOL_NAME.test(fn.name)) {
      unsupported('Anthropic tools require an OpenAI function schema');
    }
    const parameters = fn.parameters == null
      ? { type: 'object', properties: {} } : fn.parameters;
    if (!plainRecord(parameters)) unsupported('Anthropic tool parameters must be a JSON Schema object');
    if (fn.description != null && typeof fn.description !== 'string') {
      unsupported('Anthropic tool descriptions must be strings');
    }
    if (fn.strict != null && typeof fn.strict !== 'boolean') {
      unsupported('Anthropic tool strict must be a boolean');
    }
    return {
      name: fn.name,
      ...(typeof fn.description === 'string' ? { description: fn.description } : {}),
      input_schema: parameters,
      ...(fn.strict === true ? { strict: true } : {}),
    };
  });
}

function anthropicToolChoice(choice, parallelToolCalls, tools) {
  if (parallelToolCalls != null && typeof parallelToolCalls !== 'boolean') {
    unsupported('Anthropic parallel_tool_calls must be a boolean');
  }
  if (!tools && choice != null && !['auto', 'none'].includes(choice)) {
    unsupported('Anthropic tool_choice requires tools');
  }
  let mapped;
  if (choice == null || choice === 'auto') mapped = { type: 'auto' };
  else if (choice === 'required') mapped = { type: 'any' };
  else if (choice === 'none') mapped = { type: 'none' };
  else if (choice && choice.type === 'function' && choice.function && choice.function.name) {
    const name = String(choice.function.name);
    if (!tools || !tools.some((tool) => tool.name === name)) {
      unsupported('Anthropic tool_choice must name a declared tool');
    }
    mapped = { type: 'tool', name };
  } else unsupported('Anthropic tool_choice is not supported');
  if (parallelToolCalls === false && mapped.type !== 'none') mapped.disable_parallel_tool_use = true;
  return mapped;
}

function completionLimit(body) {
  const legacy = body.max_tokens;
  const modern = body.max_completion_tokens;
  if (legacy != null && modern != null && legacy !== modern) {
    unsupported('Anthropic max_tokens and max_completion_tokens must match');
  }
  const value = modern ?? legacy ?? 1024;
  if (!Number.isInteger(value) || value <= 0) {
    unsupported('Anthropic completion token limit must be a positive integer');
  }
  return value;
}

function validateSampling(body) {
  for (const field of ['temperature', 'top_p']) {
    if (body[field] != null && (typeof body[field] !== 'number'
        || !Number.isFinite(body[field]) || body[field] < 0 || body[field] > 1)) {
      unsupported(`Anthropic ${field} must be between 0 and 1`);
    }
  }
  if (body.stop != null) {
    const stops = Array.isArray(body.stop) ? body.stop : [body.stop];
    if (!stops.length || stops.some((stop) => typeof stop !== 'string' || !stop)) {
      unsupported('Anthropic stop must contain nonempty strings');
    }
  }
}

function validateRequest(kind, body = {}) {
  if (kind !== 'chat') unsupported('Anthropic supports only /v1/chat/completions');
  if (!plainRecord(body)) unsupported('Anthropic request body must be a JSON object');
  for (const field of Object.keys(body)) {
    if (!SUPPORTED_REQUEST_FIELDS.has(field)) unsupported(`Anthropic does not support ${field}`);
  }
  if (typeof body.model !== 'string' || !body.model.trim()) {
    unsupported('Anthropic requests require a model');
  }
  if (body.n != null && body.n !== 1) unsupported('Anthropic does not support n greater than 1');
  if (body.stream != null && typeof body.stream !== 'boolean') {
    unsupported('Anthropic stream must be a boolean');
  }
  translatedMessages(body.messages);
  completionLimit(body);
  validateSampling(body);
  const tools = anthropicTools(body.tools);
  anthropicToolChoice(body.tool_choice, body.parallel_tool_calls, tools);
  return true;
}

function toAnthropic(body) {
  validateRequest('chat', body);
  const { system, turns } = translatedMessages(body.messages);
  const tools = anthropicTools(body.tools);
  const toolChoice = anthropicToolChoice(body.tool_choice, body.parallel_tool_calls, tools);
  const out = {
    model: body.model,
    system,
    messages: turns,
    max_tokens: completionLimit(body),
  };
  if (tools) out.tools = tools;
  if (tools && toolChoice) out.tool_choice = toolChoice;
  if (body.temperature != null) out.temperature = body.temperature;
  if (body.top_p != null) out.top_p = body.top_p;
  if (body.stop != null) out.stop_sequences = Array.isArray(body.stop) ? body.stop : [body.stop];
  return out;
}

// Map an Anthropic response back into an OpenAI-shaped response for the caller.
function fromAnthropic(json) {
  if (!plainRecord(json) || typeof json.id !== 'string' || !json.id
      || typeof json.model !== 'string' || !json.model || !Array.isArray(json.content)) {
    unsupported('Anthropic response is malformed');
  }
  const content = json.content;
  const text = [];
  const toolCalls = [];
  for (const part of content) {
    if (part && part.type === 'text' && typeof part.text === 'string') text.push(part.text);
    else if (part && part.type === 'tool_use' && part.id && part.name
        && plainRecord(part.input)) {
      toolCalls.push({
        id: String(part.id),
        type: 'function',
        function: { name: String(part.name), arguments: JSON.stringify(part.input || {}) },
      });
    } else if (part != null) unsupported('Anthropic response contained an unsupported content block');
  }
  const stopReasons = {
    end_turn: 'stop',
    max_tokens: 'length',
    stop_sequence: 'stop',
    tool_use: 'tool_calls',
    refusal: 'content_filter',
    model_context_window_exceeded: 'length',
  };
  if (!stopReasons[json.stop_reason]) unsupported('Anthropic response stop_reason is unsupported');
  const message = {
    role: 'assistant',
    content: text.length ? text.join('') : (toolCalls.length ? null : ''),
    ...(toolCalls.length ? { tool_calls: toolCalls } : {}),
  };
  const result = {
    id: json.id,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: json.model,
    choices: [{ index: 0, message, finish_reason: stopReasons[json.stop_reason] }],
  };
  if (json.usage) {
    const promptTokens = Number(json.usage.input_tokens) || 0;
    const completionTokens = Number(json.usage.output_tokens) || 0;
    result.usage = {
      prompt_tokens: promptTokens,
      completion_tokens: completionTokens,
      total_tokens: promptTokens + completionTokens,
    };
  }
  return result;
}

async function callUpstream(kind, body, ctx) {
  validateProviderCredentials((ctx && ctx.provider) || 'anthropic', ctx && ctx.upstreamApiKey);
  const base = normalizeGatewayUrl(ctx.upstreamBaseUrl || 'https://api.anthropic.com', {
    label: 'gateway upstream URL',
    allowInsecureDev: ctx.allowInsecureHttp === true,
    production: String(process.env.NODE_ENV || '').toLowerCase() === 'production',
  });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ctx.requestTimeoutMs);
  try {
    const res = await fetch(base + '/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': ctx.upstreamApiKey || '',
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(toAnthropic(body)),
      signal: controller.signal,
      redirect: 'error',
    });
    const { text } = await readBoundedText(res, {
      maxBytes: ctx.maxUpstreamResponseBytes,
      timeoutMs: ctx.requestTimeoutMs,
      label: 'gateway upstream response',
    });
    let json = null;
    try { json = text ? fromAnthropic(JSON.parse(text)) : null; } catch { json = null; }
    return { ok: res.ok, status: res.status, json, rawText: text };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = {
  name: 'anthropic',
  requestText: canonical.requestText,
  applyRedactedRequest: canonical.applyRedactedRequest,
  responseText: canonical.responseText,
  applyResponseText: canonical.applyResponseText,
  callUpstream,
  validateRequest,
  toAnthropic,
  fromAnthropic,
};
