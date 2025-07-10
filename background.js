let currentTab;
let version = "1.0";

chrome.tabs.query({ currentWindow: true, active: true }).then((tabs) => {
  if (tabs && tabs.length > 0) {
    currentTab = tabs[0];
    if (currentTab.id) {
      chrome.scripting.executeScript({
        target: { tabId: currentTab.id },
        files: ["inject.js"]
      });
    }
  }
});

chrome.storage.sync.get(["ranOnce"], (ranOnce) => {
  if (!ranOnce.ranOnce) {
    chrome.storage.sync.set({ ranOnce: true });
    chrome.storage.sync.set({ originDenyList: ["https://www.google.com"] });
  }
});

// =============================
// 1) REGEX PATTERNS & VARIABLES
// =============================
let specifics = {
  // ... (keep all your existing regex patterns unchanged) ...
};

let generics = {
  "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]",
  "Generic Secret": "[sS][eE][cC][rR][eE][tT].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]"
};

let aws = {
  "AWS API Key": "((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})"
};

let denyList = ["AIDAAAAAAAAAAAAAAAAA"];

function checkData(data, src, regexes, fromEncoded = false, parentUrl = undefined, parentOrigin = undefined) {
  let findings = [];
  for (let key in regexes) {
    let re = new RegExp(regexes[key]);
    let match = re.exec(data);
    if (Array.isArray(match)) {
      match = match.toString();
    }
    if (denyList.includes(match)) {
      continue;
    }
    if (match) {
      let finding = { src, match, key, encoded: fromEncoded, parentUrl };
      findings.push(finding);
    }
  }

  if (findings.length > 0 && parentOrigin) {
    chrome.storage.sync.get(["leakedKeys"], function (result) {
      chrome.storage.sync.get(["uniqueByHostname"], function (uniqueByHostname) {
        let keys = {};
        if (!Array.isArray(result.leakedKeys) && result.leakedKeys) {
          keys = result.leakedKeys;
        }

        if (!keys[parentOrigin]) {
          keys[parentOrigin] = [];
        }
        for (let finding of findings) {
          let newFinding = true;
          
          if (uniqueByHostname && uniqueByHostname["uniqueByHostname"]) {
            for (let oldKey of keys[parentOrigin]) {
              const oldHost = extractHostname(oldKey["src"]);
              const newHost = extractHostname(finding["src"]);
              if (
                oldHost &&
                newHost &&
                oldHost === newHost &&
                oldKey["match"] === finding["match"] &&
                oldKey["key"] === finding["key"] &&
                oldKey["encoded"] === finding["encoded"]
              ) {
                newFinding = false;
                break;
              }
            }
          } else {
            for (let oldKey of keys[parentOrigin]) {
              if (
                oldKey["src"] === finding["src"] &&
                oldKey["match"] === finding["match"] &&
                oldKey["key"] === finding["key"] &&
                oldKey["encoded"] === finding["encoded"] &&
                oldKey["parentUrl"] === finding["parentUrl"]
              ) {
                newFinding = false;
                break;
              }
            }
          }

          if (newFinding) {
            keys[parentOrigin].push(finding);
            chrome.storage.sync.set({ leakedKeys: keys }, function () {
              updateTabAndAlert(finding);
            });
          }
        }
      });
    });
  }

  let decodedStrings = getDecodedb64(data);
  for (let encoded of decodedStrings) {
    checkData(encoded[1], src, regexes, encoded[0], parentUrl, parentOrigin);
  }
}

function updateTabAndAlert(finding) {
  let key = finding["key"];
  let src = finding["src"];
  let match = finding["match"];
  let fromEncoded = finding["encoded"];

  chrome.storage.sync.get(["alerts"], function (result) {
    chrome.storage.sync.get(["notifications"], function (notifications) {
      let alertText;
      let notifyText;
      if (fromEncoded) {
        alertText = key + ": " + match + " found in " + src + " decoded from " + fromEncoded.substring(0, 9) + "...";
        notifyText = `${match.substring(0, 30)}... (orig was encoded) found in ${src}`;
      } else {
        alertText = key + ": " + match + " found in " + src;
        notifyText = `${match.substring(0, 30)}... found in ${src}`;
      }

      if (result.alerts === undefined || result.alerts) {
        chrome.tabs.query({ currentWindow: true, active: true }).then((tabs) => {
          if (tabs && tabs.length > 0) {
            chrome.scripting.executeScript({
              target: { tabId: tabs[0].id },
              func: (msg) => alert(msg),
              args: [alertText]
            });
          }
        });
      }

      if (notifications && notifications["notifications"]) {
        chrome.notifications.create(src + new Date(), {
          type: "basic",
          iconUrl: "icon128.png",
          title: `ZeusLeak | ${key}`,
          message: notifyText,
          priority: 2
        });
      }
    });
  });

  updateTab();
}

function updateTab() {
  chrome.tabs.query({ currentWindow: true, active: true }).then((tabs) => {
    if (!tabs || !tabs.length) return;
    let tabId = tabs[0].id;
    let tabUrl = tabs[0].url;
    let origin;
    
    try {
      origin = new URL(tabUrl).origin;
    } catch (e) {
      // Invalid URL, clear badge and exit
      chrome.action.setBadgeText({ text: "", tabId: tabId });
      return;
    }

    chrome.storage.sync.get(["leakedKeys"], function (result) {
      if (result.leakedKeys && Array.isArray(result.leakedKeys[origin])) {
        let originKeys = result.leakedKeys[origin].length.toString();
        chrome.action.setBadgeText({ text: originKeys, tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#ff0000", tabId: tabId });
      } else {
        chrome.action.setBadgeText({ text: "", tabId: tabId });
      }
    });
  });
}

chrome.tabs.onActivated.addListener(function (activeInfo) {
  updateTab();
});

function getStringsOfSet(word, char_set, threshold = 20) {
  let count = 0;
  let letters = "";
  let strings = [];
  if (!word) {
    return [];
  }
  for (let char of word) {
    if (char_set.indexOf(char) > -1) {
      letters += char;
      count += 1;
    } else {
      if (count > threshold) {
        strings.push(letters);
      }
      letters = "";
      count = 0;
    }
  }
  if (count > threshold) {
    strings.push(letters);
  }
  return strings;
}

function getDecodedb64(inputString) {
  let b64CharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  let encodeds = getStringsOfSet(inputString, b64CharSet);
  let decodeds = [];
  for (let encoded of encodeds) {
    try {
      let decoded = [encoded, atob(encoded)];
      decodeds.push(decoded);
    } catch (e) {
      // Ignore decoding errors
    }
  }
  return decodeds;
}

function extractHostname(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return null;
  }
}

function checkIfOriginDenied(check_url, cb) {
  chrome.storage.sync.get(["originDenyList"], function (result) {
    let skip = false;
    if (!result.originDenyList) {
      cb(skip);
      return;
    }
    let originDenyList = result.originDenyList.filter((u) => u.length > 1);
    for (let origin of originDenyList) {
      try {
        if (check_url.startsWith(origin)) {
          skip = true;
          break;
        }
      } catch (e) {
        // Invalid URL comparison, skip
      }
    }
    cb(skip);
  });
}

function checkForGitDir(data, url) {
  if (data.startsWith("[core]")) {
    chrome.tabs.query({ currentWindow: true, active: true }).then((tabs) => {
      if (tabs && tabs.length > 0) {
        chrome.scripting.executeScript({
          target: { tabId: tabs[0].id },
          func: (msg) => alert(msg),
          args: [`.git dir found in ${url}`]
        });
      }
    });
  }
}

chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
  chrome.storage.sync.get(["generics"], function (useGenerics) {
    chrome.storage.sync.get(["specifics"], function (useSpecifics) {
      chrome.storage.sync.get(["aws"], function (useAws) {
        chrome.storage.sync.get(["checkEnv"], function (checkEnv) {
          chrome.storage.sync.get(["checkGit"], function (checkGit) {
            let regexes = {};

            if (useGenerics["generics"] || useGenerics["generics"] === undefined) {
              regexes = { ...regexes, ...generics };
            }
            if (useSpecifics["specifics"] || useSpecifics["specifics"] === undefined) {
              regexes = { ...regexes, ...specifics };
            }
            if (useAws["aws"] || useAws["aws"] === undefined) {
              regexes = { ...regexes, ...aws };
            }

            if (request.scriptUrl) {
              let js_url = request.scriptUrl;
              let parentUrl = request.parentUrl;
              let parentOrigin = request.parentOrigin;
              checkIfOriginDenied(js_url, function (skip) {
                if (!skip) {
                  fetch(js_url, { credentials: "include" })
                    .then((response) => response.text())
                    .then((data) => checkData(data, js_url, regexes, false, parentUrl, parentOrigin))
                    .catch((err) => console.error("Fetch error:", err));
                }
              });
            } else if (request.pageBody) {
              checkIfOriginDenied(request.origin, function (skip) {
                if (!skip) {
                  checkData(request.pageBody, request.origin, regexes, false, request.parentUrl, request.parentOrigin);
                }
              });
            } else if (request.envFile) {
              if (checkEnv["checkEnv"]) {
                checkIfOriginDenied(request.envFile, function (skip) {
                  if (!skip) {
                    fetch(request.envFile, { credentials: "include" })
                      .then((response) => response.text())
                      .then((data) =>
                        checkData(data, ".env file at " + request.envFile, regexes, false, request.parentUrl, request.parentOrigin)
                      )
                      .catch((err) => console.error("Fetch error:", err));
                  }
                });
              }
            } else if (request.openTabs) {
              for (let tab of request.openTabs) {
                chrome.tabs.create({ url: tab });
              }
            } else if (request.gitDir) {
              if (checkGit["checkGit"]) {
                checkIfOriginDenied(request.gitDir, function (skip) {
                  if (!skip) {
                    fetch(request.gitDir, { credentials: "include" })
                      .then((response) => response.text())
                      .then((data) => checkForGitDir(data, request.gitDir))
                      .catch((err) => console.error("Fetch error:", err));
                  }
                });
              }
            }
          });
        });
      });
    });
  });
});