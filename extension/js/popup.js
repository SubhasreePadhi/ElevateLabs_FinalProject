// js/popup.js

document.addEventListener('DOMContentLoaded', () => {
    const blockedCountElement = document.getElementById('blockedCount');
    const optionsBtn = document.getElementById('optionsBtn');
    const whitelistCurrentSiteBtn = document.getElementById('whitelistCurrentSiteBtn');

    // Request blocked count from background script
    chrome.runtime.sendMessage({ action: 'getBlockedCount' }, (response) => {
        if (response && response.count !== undefined) {
            blockedCountElement.textContent = response.count;
        } else {
            blockedCountElement.textContent = 'N/A'; // Fallback
        }
    });

    // Open options page
    optionsBtn.addEventListener('click', () => {
        chrome.runtime.openOptionsPage();
    });

    // Whitelist current site
    whitelistCurrentSiteBtn.addEventListener('click', async () => {
        let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            try {
                const url = new URL(tab.url);
                const domain = url.hostname;
                if (domain) {
                    // Send message to background script to add to whitelist
                    chrome.runtime.sendMessage({ action: 'addRule', domain: domain, ruleType: 'allow' }, (response) => {
                        if (response.status === 'success') {
                            alertMessage('Site whitelisted: ' + domain, 'success');
                            chrome.tabs.reload(tab.id); // Reload tab to apply new rule
                        } else {
                            alertMessage('Error whitelisting site: ' + response.message, 'error');
                        }
                    });
                }
            } catch (e) {
                alertMessage('Invalid URL for whitelisting.', 'error');
            }
        }
    });

    // Custom alert message function (replaces native alert)
    function alertMessage(message, type) {
        // Create a simple overlay message
        let msgDiv = document.createElement('div');
        msgDiv.textContent = message;
        msgDiv.style.cssText = `
            position: fixed;
            top: 10px;
            left: 50%;
            transform: translateX(-50%);
            background-color: ${type === 'success' ? '#4CAF50' : '#f44336'};
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            z-index: 10000;
            font-size: 0.9em;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            opacity: 0;
            transition: opacity 0.3s ease-in-out;
        `;
        document.body.appendChild(msgDiv);

        // Fade in
        setTimeout(() => msgDiv.style.opacity = 1, 10);

        // Fade out and remove
        setTimeout(() => {
            msgDiv.style.opacity = 0;
            msgDiv.addEventListener('transitionend', () => msgDiv.remove());
        }, 3000);
    }
});
