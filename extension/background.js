// background.js

let blockedCount = 0; // Initialize counter for blocked requests

// Function to update the badge count on the extension icon
async function updateBadge() 
{
  await chrome.action.setBadgeText({ text: blockedCount.toString() });
  await chrome.action.setBadgeBackgroundColor({ color: '#FF0000' }); // Red color for blocked status
}

// Function to reset the badge count for a new page load
function resetBadge() 
{
  blockedCount = 0;
  updateBadge();
}

// Listen for network requests completed and update the blocked count
// Note: declarativeNetRequest API blocks requests before webRequest events.
// To count blocked items, we can listen to "onBeforeRequest" and check if it would be blocked,
// or more reliably, use the "onRuleMatchedDebug" API (developer mode only) or infer from declarativeNetRequest rules.
// For simplicity, we'll manually increment based on a listener in this example,
// but for true blocking counts, you'd need a more sophisticated approach or debug API.

// A more robust way to count: listen to `onBeforeRequest` and if the URL matches a known tracker,
// increment the count. This is a heuristic as `onBeforeRequest` fires *before* `declarativeNetRequest` blocks.
// A perfect count for declarativeNetRequest requires `onRuleMatchedDebug` (developer mode only)
// or maintaining dynamic rules and checking against them programmatically.

// Let's use a simplified approach for demonstration:
// When the tab updates (i.e., new page load), reset the count.

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading') {
    resetBadge();
  }
});

// Listener for declarativeNetRequest operations to count blocked items (more complex in practice)
// This is a conceptual example. Actual counting from declarativeNetRequest blocks is tricky without onRuleMatchedDebug.
// For a real-world app, you might just count requests that MATCH your rule set *before* they are sent.
// Here, we'll use a simpler heuristic for demo purposes: increment when we know a domain *would* be blocked.

// Store a set of all known blocking rules (static + dynamic) to check against
let allBlockingRules = new Set();

async function updateAllBlockingRules() {
  const staticRules = await chrome.declarativeNetRequest.getEnabledRulesets();
  const dynamicRules = await chrome.declarativeNetRequest.getDynamicRules();

  allBlockingRules.clear();
  // For simplicity, this example doesn't parse the actual filters from rules.json or dynamic rules.
  // In a real application, you'd parse `urlFilter` from each rule and add to this set.
  // This is a placeholder. A more direct way to count is to use `onBeforeRequest` and check
  // against your *internal* list of trackers.

  // Example: If you have a separate list of tracker domains in an array
  // const trackerDomains = ["google-analytics.com", "facebook.com"];
  // For this demo, let's assume `onBeforeRequest` is sufficient to check against our domains.
}

// Initialize on startup
chrome.runtime.onInstalled.addListener(() => {
  resetBadge();
  updateAllBlockingRules(); // Populate rules on install
});

chrome.runtime.onStartup.addListener(() => {
  resetBadge();
  updateAllBlockingRules(); // Populate rules on browser startup
});


// Simplified counting mechanism: When a request is about to be made, check if its URL
// contains any of our known tracker domains. This is *before* declarativeNetRequest blocks it.
// This is a heuristic, not a direct count of declarativeNetRequest blocks.
const knownTrackerDomains = ["google-analytics.com", "facebook.com/tr"]; // Keep this in sync with rules.json or a master list

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Check if the URL matches any known tracker domain
    const isTracker = knownTrackerDomains.some(domain => details.url.includes(domain));
    if (isTracker) {
      blockedCount++;
      updateBadge();
    }
    // No need to return {cancel: true} here, declarativeNetRequest handles the blocking.
    // This listener is purely for counting.
  },
  { urls: ["<all_urls>"] },
  ["blocking"] // Required to allow inspecting the request details, even if not cancelling.
);


// Functions for Whitelist/Blacklist management (called from options.js)
// Note: Dynamic rules require a rule ID management to avoid conflicts.
let nextDynamicRuleId = 1000; // Start dynamic rule IDs high to avoid conflict with static rules

async function addDynamicRule(domain, type) {
  const rules = await chrome.declarativeNetRequest.getDynamicRules();
  const existingRule = rules.find(rule => rule.condition.urlFilter === `||${domain}^` && rule.action.type === type);

  if (existingRule) {
    console.warn(`Rule for ${domain} (${type}) already exists.`);
    return;
  }

  const newRule = {
    id: nextDynamicRuleId++, // Assign a unique ID
    priority: 2, // Higher priority than default static rules, lower than explicit allow
    action: { type: type === 'block' ? 'block' : 'allow' }, // 'allow' for whitelist, 'block' for blacklist
    condition: {
      urlFilter: `||${domain}^`,
      resourceTypes: ["script", "image", "media", "stylesheet", "font", "xmlhttprequest", "ping", "csp_report", "main_frame", "sub_frame", "object", "other"]
    }
  };

  try {
    // Remove existing rule if it was of opposite type for the same domain
    const oppositeType = type === 'block' ? 'allow' : 'block';
    const oppositeRule = rules.find(rule => rule.condition.urlFilter === `||${domain}^` && rule.action.type === oppositeType);
    if (oppositeRule) {
      await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [oppositeRule.id] });
      console.log(`Removed opposite rule for ${domain}`);
    }

    await chrome.declarativeNetRequest.updateDynamicRules({ addRules: [newRule] });
    console.log(`Added dynamic ${type} rule for: ${domain}`);
    updateAllBlockingRules(); // Refresh internal rule list
  } catch (error) {
    console.error(`Error adding dynamic rule for ${domain}:`, error);
  }
}

async function removeDynamicRule(domain) {
  const rules = await chrome.declarativeNetRequest.getDynamicRules();
  const ruleToRemove = rules.find(rule => rule.condition.urlFilter === `||${domain}^`);

  if (ruleToRemove) {
    try {
      await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [ruleToRemove.id] });
      console.log(`Removed dynamic rule for: ${domain}`);
      updateAllBlockingRules(); // Refresh internal rule list
    } catch (error) {
      console.error(`Error removing dynamic rule for ${domain}:`, error);
    }
  } else {
    console.warn(`No dynamic rule found for ${domain}.`);
  }
}

// Make functions available to other parts of the extension (e.g., popup.js, options.js)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getBlockedCount') {
    sendResponse({ count: blockedCount });
  } else if (request.action === 'addRule') {
    addDynamicRule(request.domain, request.ruleType).then(() => {
      sendResponse({ status: 'success' });
    }).catch(error => {
      sendResponse({ status: 'error', message: error.message });
    });
    return true; // Indicates async response
  } else if (request.action === 'removeRule') {
    removeDynamicRule(request.domain).then(() => {
      sendResponse({ status: 'success' });
    }).catch(error => {
      sendResponse({ status: 'error', message: error.message });
    });
    return true; // Indicates async response
  } else if (request.action === 'getRules') {
    chrome.declarativeNetRequest.getDynamicRules().then(rules => {
      const whitelist = rules.filter(r => r.action.type === 'allow').map(r => r.condition.urlFilter.replace('||', '').replace('^', ''));
      const blacklist = rules.filter(r => r.action.type === 'block' && r.priority > 1).map(r => r.condition.urlFilter.replace('||', '').replace('^', ''));
      sendResponse({ whitelist, blacklist });
    }).catch(error => {
      sendResponse({ status: 'error', message: error.message });
    });
    return true; // Indicates async response
  }
});

// Set badge text to 0 on install to ensure it's visible.
chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeText({ text: '0' });
  chrome.action.setBadgeBackgroundColor({ color: '#FF0000' });
});