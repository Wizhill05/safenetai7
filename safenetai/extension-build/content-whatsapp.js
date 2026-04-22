// PhishGuard WhatsApp Content Script

const PHISHGUARD_PLATFORM = "whatsapp";
const analyzedCache = new Map();
let periodicRescanId = null;

function detectPlatform() {
  const host = window.location.hostname;
  if (host === "web.whatsapp.com") {
    return "whatsapp";
  }
  if (host.includes("linkedin.com") && window.location.pathname.includes("/messaging")) {
    return "linkedin";
  }
  return "unknown";
}

function normalizeMessageText(text) {
  return (text || "").replace(/\s+/g, " ").trim();
}

function hashMessage(text) {
  const input = `${PHISHGUARD_PLATFORM}:${text}`;
  let hash = 5381;
  for (let i = 0; i < input.length; i += 1) {
    hash = (hash * 33) ^ input.charCodeAt(i);
  }
  return String(hash >>> 0);
}

function getChatRoot() {
  return document.querySelector("#main") || document.querySelector("[data-testid='conversation-panel-body']") || document.body;
}

function isLikelyMessageNode(node) {
  if (!(node instanceof HTMLElement)) return false;
  if (node.closest("[contenteditable='true']")) return false;

  const text = normalizeMessageText(node.textContent || "");
  if (text.length < 8) return false;

  return (
    node.closest(".message-in") ||
    node.closest(".message-out") ||
    node.closest("[data-testid='msg-container']")
  );
}

function getIncomingMessageNodes(root = document) {
  const selectors = [
    ".message-in .copyable-text .selectable-text",
    ".message-in .copyable-text",
    ".message-out .copyable-text .selectable-text",
    ".message-out .copyable-text",
    "[data-testid='msg-container'] .copyable-text .selectable-text",
    "[data-testid='msg-container'] .selectable-text",
    "[data-testid='msg-container'] .copyable-text",
    "div.copyable-text[data-pre-plain-text]",
  ];

  const nodes = [];
  const seen = new Set();
  selectors.forEach((selector) => {
    root.querySelectorAll(selector).forEach((node) => {
      if (node && node.textContent && !seen.has(node) && isLikelyMessageNode(node)) {
        seen.add(node);
        nodes.push(node);
      }
    });
  });
  return nodes;
}

function resolveBubbleContainer(node) {
  return node.closest(".message-in") || node.closest(".message-out") || node.parentElement || node;
}

async function analyzeWithGemini(messageText) {
  try {
    const response = await chrome.runtime.sendMessage({
      action: "analyzeChatMessage",
      platform: PHISHGUARD_PLATFORM,
      messageText,
    });

    if (!response || response.error) {
      return {
        isScam: false,
        riskScore: 0,
        scamType: "unknown",
        explanation: "AI analysis unavailable right now.",
      };
    }

    return response;
  } catch (error) {
    console.error("PhishGuard WhatsApp Gemini error:", error);
    return {
      isScam: false,
      riskScore: 0,
      scamType: "unknown",
      explanation: "AI analysis unavailable right now.",
    };
  }
}

function handleReport(messageText, analysis) {
  chrome.runtime.sendMessage({
    action: "reportScamMessage",
    platform: PHISHGUARD_PLATFORM,
    messageText,
    analysis,
    pageUrl: window.location.href,
    createdAt: new Date().toISOString(),
  });
}

function injectWarningUI(messageNode, analysis, messageText) {
  const bubble = resolveBubbleContainer(messageNode);
  if (!bubble || bubble.querySelector(".phishguard-warning")) {
    return;
  }

  const warning = document.createElement("div");
  warning.className = "phishguard-warning";
  warning.style.cssText = [
    "margin-top: 6px",
    "padding: 10px 12px",
    "border-radius: 10px",
    "background: rgba(239, 68, 68, 0.16)",
    "border: 1px solid rgba(239, 68, 68, 0.55)",
    "color: #ffd8d8",
    "font-size: 12px",
    "line-height: 1.4",
    "font-family: Segoe UI, Arial, sans-serif",
  ].join(";");

  const title = document.createElement("div");
  title.textContent = "⚠ Scam Detected";
  title.style.cssText = "font-weight: 700; margin-bottom: 4px;";

  const details = document.createElement("div");
  details.textContent = `Risk Score: ${analysis.riskScore} | Scam Type: ${analysis.scamType}`;

  const reason = document.createElement("div");
  reason.textContent = analysis.explanation || "Suspicious scam pattern detected.";
  reason.style.cssText = "margin-top: 4px;";

  const reportBtn = document.createElement("button");
  reportBtn.type = "button";
  reportBtn.textContent = "Report";
  reportBtn.style.cssText = [
    "margin-top: 8px",
    "padding: 5px 10px",
    "border: 1px solid rgba(239, 68, 68, 0.8)",
    "background: rgba(239, 68, 68, 0.22)",
    "color: #ffe7e7",
    "border-radius: 8px",
    "cursor: pointer",
    "font-size: 11px",
    "font-weight: 600",
  ].join(";");

  reportBtn.addEventListener("click", () => {
    handleReport(messageText, analysis);
    reportBtn.textContent = "Reported";
    reportBtn.disabled = true;
    reportBtn.style.opacity = "0.7";
    reportBtn.style.cursor = "default";
  });

  warning.appendChild(title);
  warning.appendChild(details);
  warning.appendChild(reason);
  warning.appendChild(reportBtn);
  bubble.appendChild(warning);
}

async function processMessageNode(node) {
  if (!node || node.dataset.phishguardAnalyzed === "1") {
    return;
  }

  const messageText = normalizeMessageText(node.textContent || "");
  if (!messageText || messageText.length < 6) {
    node.dataset.phishguardAnalyzed = "1";
    return;
  }

  const hash = hashMessage(messageText);
  node.dataset.phishguardHash = hash;

  if (analyzedCache.has(hash)) {
    const cachedResult = analyzedCache.get(hash);
    node.dataset.phishguardAnalyzed = "1";
    if (cachedResult?.isScam) {
      injectWarningUI(node, cachedResult, messageText);
    }
    return;
  }

  const analysis = await analyzeWithGemini(messageText);
  const lowerText = messageText.toLowerCase();
  const suspiciousWords = [
    "urgent",
    "verify",
    "account",
    "suspended",
    "suspend",
    "blocked",
    "block",
    "permanent block",
    "avoid",
    "otp",
    "password",
    "bank",
    "kyc",
    "fee",
    "payment",
    "click",
    "shortlisted",
    "internship",
  ];
  let score = 0;
  suspiciousWords.forEach((word) => {
    if (lowerText.includes(word)) score += 1;
  });
  if (lowerText.includes("http://") || lowerText.includes("https://")) score += 2;

  const hasSuspensionPattern =
    (lowerText.includes("account") && (lowerText.includes("suspend") || lowerText.includes("blocked"))) ||
    (lowerText.includes("verify") && lowerText.includes("account"));
  if (hasSuspensionPattern) score += 2;

  const fallbackAnalysis = {
    isScam: score >= 3,
    riskScore: Math.min(95, 40 + score * 7),
    scamType: "phishing",
    explanation: "Multiple scam indicators detected locally (urgency, credential/payment cues, and link patterns).",
  };

  const finalAnalysis = analysis.isScam ? analysis : fallbackAnalysis;
  analyzedCache.set(hash, finalAnalysis);
  node.dataset.phishguardAnalyzed = "1";

  if (finalAnalysis.isScam) {
    injectWarningUI(node, finalAnalysis, messageText);
  }
}

function observeMessages() {
  const root = getChatRoot();
  if (!root) {
    return;
  }

  getIncomingMessageNodes(root).forEach((node) => {
    processMessageNode(node);
  });

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      mutation.addedNodes.forEach((addedNode) => {
        if (!(addedNode instanceof HTMLElement)) {
          return;
        }

        if (
          addedNode.matches &&
          addedNode.matches(
            ".message-in .copyable-text, .message-in .selectable-text, .message-out .copyable-text, .message-out .selectable-text, [data-testid='msg-container'] .copyable-text, [data-testid='msg-container'] .selectable-text"
          )
        ) {
          processMessageNode(addedNode);
        }

        getIncomingMessageNodes(addedNode).forEach((node) => {
          processMessageNode(node);
        });
      });
    }
  });

  observer.observe(root, {
    childList: true,
    subtree: true,
  });

  if (periodicRescanId) {
    clearInterval(periodicRescanId);
  }

  periodicRescanId = setInterval(() => {
    getIncomingMessageNodes(getChatRoot()).forEach((node) => {
      processMessageNode(node);
    });
  }, 2000);
}

(function init() {
  const platform = detectPlatform();
  if (platform !== "whatsapp") {
    return;
  }

  observeMessages();
})();
