// js/options.js

document.addEventListener('DOMContentLoaded', () => {
    const domainInput = document.getElementById('domainInput');
    const ruleTypeSelect = document.getElementById('ruleTypeSelect');
    const addRuleBtn = document.getElementById('addRuleBtn');
    const whitelistElement = document.getElementById('whitelist');
    const blacklistElement = document.getElementById('blacklist');

    // Function to render rules in the UI
    function renderRules(whitelist, blacklist) {
        whitelistElement.innerHTML = ''; // Clear current list
        blacklistElement.innerHTML = ''; // Clear current list

        if (whitelist.length === 0) {
            whitelistElement.innerHTML = '<li class="empty-message">No sites whitelisted yet.</li>';
        } else {
            whitelist.forEach(domain => {
                whitelistElement.appendChild(createRuleListItem(domain, 'allow'));
            });
        }

        if (blacklist.length === 0) {
            blacklistElement.innerHTML = '<li class="empty-message">No sites blacklisted yet.</li>';
        } else {
            blacklist.forEach(domain => {
                blacklistElement.appendChild(createRuleListItem(domain, 'block'));
            });
        }
    }

    // Function to create a list item for a rule
    function createRuleListItem(domain, type) {
        const li = document.createElement('li');
        const domainSpan = document.createElement('span');
        domainSpan.textContent = domain;
        li.appendChild(domainSpan);

        const removeBtn = document.createElement('button');
        removeBtn.textContent = 'Remove';
        removeBtn.className = 'remove-btn';
        removeBtn.addEventListener('click', () => {
            // Send message to background script to remove rule
            chrome.runtime.sendMessage({ action: 'removeRule', domain: domain }, (response) => {
                if (response.status === 'success') {
                    alertMessage(`Rule for ${domain} removed.`, 'success');
                    loadRules(); // Reload rules to update UI
                } else {
                    alertMessage(`Error removing rule: ${response.message}`, 'error');
                }
            });
        });
        li.appendChild(removeBtn);
        return li;
    }

    // Function to load and display rules from background script
    function loadRules() {
        chrome.runtime.sendMessage({ action: 'getRules' }, (response) => {
            if (response && response.whitelist && response.blacklist) {
                renderRules(response.whitelist, response.blacklist);
            } else {
                alertMessage(`Error loading rules: ${response.message}`, 'error');
            }
        });
    }

    // Add rule button click listener
    addRuleBtn.addEventListener('click', () => {
        const domain = domainInput.value.trim();
        const ruleType = ruleTypeSelect.value;

        if (domain) {
            // Basic domain validation (can be more robust)
            if (!domain.includes('.')) {
                alertMessage('Please enter a valid domain (e.g., example.com).', 'error');
                return;
            }

            chrome.runtime.sendMessage({ action: 'addRule', domain: domain, ruleType: ruleType }, (response) => {
                if (response.status === 'success') {
                    alertMessage(`Rule for ${domain} (${ruleType}) added.`, 'success');
                    domainInput.value = ''; // Clear input field
                    loadRules(); // Reload rules to update UI
                } else {
                    alertMessage(`Error adding rule: ${response.message}`, 'error');
                }
            });
        } else {
            alertMessage('Please enter a domain.', 'error');
        }
    });

    // Custom alert message function (replaces native alert)
    function alertMessage(message, type) {
        // Create a simple overlay message
        let msgDiv = document.createElement('div');
        msgDiv.textContent = message;
        msgDiv.style.cssText = `
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            background-color: ${type === 'success' ? '#4CAF50' : '#f44336'};
            color: white;
            padding: 12px 25px;
            border-radius: 8px;
            z-index: 10000;
            font-size: 1em;
            box-shadow: 0 4px 10px rgba(0,0,0,0.3);
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

    // Initial load of rules when the options page is opened
    loadRules();
});
