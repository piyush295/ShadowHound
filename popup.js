document.addEventListener('DOMContentLoaded', function() {
    // Initialize accordion functionality
    const acc = document.getElementsByClassName('accordion');
    for (let i = 0; i < acc.length; i++) {
        acc[i].addEventListener('click', function() {
            this.classList.toggle('active');
            const panel = this.nextElementSibling;
            panel.classList.toggle('open');
            
            // Only load data when opening the panel
            if (panel.classList.contains('open')) {
                handlePanelOpen(this, panel);
            }
        });
    }

    // Initialize toggle switches
    const toggles = ["generics", "specifics", "aws", "checkEnv", "checkGit", 
                    "alerts", "notifications", "uniqueByHostname"];
    
    const toggleDefaults = {
        "generics": true,
        "specifics": true,
        "aws": true,
        "checkEnv": false,
        "checkGit": false,
        "alerts": true,
        "notifications": true,
        "uniqueByHostname": false
    };

    // Initialize toggle switches with storage values
    toggles.forEach(toggle => {
        chrome.storage.sync.get([toggle], result => {
            const checkbox = document.getElementById(toggle);
            if (result[toggle] === undefined) {
                checkbox.checked = toggleDefaults[toggle];
                chrome.storage.sync.set({ [toggle]: toggleDefaults[toggle] });
            } else {
                checkbox.checked = result[toggle];
            }
        });

        document.getElementById(toggle).addEventListener('change', function() {
            chrome.storage.sync.set({ [toggle]: this.checked });
        });
    });

    // Initialize other UI components
    initDenyList();
    initFindingsButtons();
    initTabOpener();
});

function handlePanelOpen(button, panel) {
    if (button.textContent.includes('Deny List')) {
        loadDenyList();
    } else if (button.textContent.includes('Findings')) {
        loadFindings();
    }
}

function initDenyList() {
    const denyListElement = document.getElementById('denyList');
    const updateDenyList = () => {
        const denyList = denyListElement.value.split(',')
            .map(item => item.trim())
            .filter(item => item);
        chrome.storage.sync.set({ originDenyList: denyList });
    };

    denyListElement.addEventListener('input', updateDenyList);
    denyListElement.addEventListener('paste', updateDenyList);
}

function initFindingsButtons() {
    // Clear current origin findings
    document.getElementById('clearOriginFindings').addEventListener('click', () => {
        chrome.tabs.query({ active: true, currentWindow: true }).then(tabs => {
            const url = tabs[0]?.url;
            if (!url) return;

            try {
                const origin = new URL(url).origin;
                chrome.storage.sync.get('leakedKeys', ({ leakedKeys = {} }) => {
                    delete leakedKeys[origin];
                    chrome.storage.sync.set({ leakedKeys });
                    chrome.action.setBadgeText({ text: '' });
                    document.getElementById('findingList').innerHTML = '';
                });
            } catch (error) {
                console.error('Invalid URL:', error);
            }
        });
    });

    // Clear all findings
    document.getElementById('clearAllFindings').addEventListener('click', () => {
        chrome.storage.sync.set({ leakedKeys: {} });
        chrome.action.setBadgeText({ text: '' });
        document.getElementById('findingList').innerHTML = '';
    });

    // Download findings
    document.getElementById('downloadAllFindings').addEventListener('click', downloadCSV);
}

function initTabOpener() {
    document.getElementById('openTabs').addEventListener('click', () => {
        const rawTabList = document.getElementById('tabList').value;
        const tabList = rawTabList.split(',')
            .map(item => item.trim())
            .filter(item => item);
        
        tabList.forEach(url => {
            if (isValidUrl(url)) {
                chrome.tabs.create({ url });
            }
        });
    });
}

function loadDenyList() {
    const denyListElement = document.getElementById('denyList');
    chrome.storage.sync.get('originDenyList', ({ originDenyList = [] }) => {
        denyListElement.value = originDenyList.join(', ');
    });
}

function loadFindings() {
    chrome.tabs.query({ active: true, currentWindow: true }).then(tabs => {
        const url = tabs[0]?.url;
        if (!url) return;

        try {
            const origin = new URL(url).origin;
            chrome.storage.sync.get('leakedKeys', ({ leakedKeys = {} }) => {
                const findings = leakedKeys[origin] || [];
                const listElement = document.getElementById('findingList');
                listElement.innerHTML = findings.map(f => `
                    <li>
                        <strong>${htmlEntities(f.key)}</strong><br>
                        ${htmlEntities(f.match.substring(0, 50))}...<br>
                        <small>Found in: ${htmlEntities(f.src)}</small>
                    </li>
                `).join('');
            });
        } catch (error) {
            console.error('Error loading findings:', error);
        }
    });
}

function downloadCSV() {
    chrome.storage.sync.get('leakedKeys', ({ leakedKeys = {} }) => {
        const csvContent = Object.entries(leakedKeys)
            .flatMap(([origin, findings]) => 
                findings.map(f => [
                    `"${origin}"`,
                    `"${f.src}"`,
                    `"${f.parentUrl}"`,
                    `"${f.key}"`,
                    `"${f.match}"`,
                    `"${f.encoded}"`
                ].join(','))
            ).join('\n');

        if (!csvContent) {
            alert('No findings to download!');
            return;
        }

        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        
        chrome.downloads.download({
            url: url,
            filename: 'ShadowHound_findings.csv',
            conflictAction: 'uniquify'
        });
    });
}

// Helper functions
function htmlEntities(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}
