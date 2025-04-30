let findings = [];
let scanSettings = {
  scanInlineScripts: true,
  scanExternalScripts: true,
  scanWindowObjects: true,
  validateOnScan: false,
  showPopupOnScan: true,
};

// Helper function to deduplicate findings
function dedupFindings(findings) {
  const seen = new Map();

  return findings.reduce((unique, finding) => {
    const key = finding.extractedValue;
    if (!seen.has(key)) {
      // Convert single source to array for consistency
      seen.set(key, {
        ...finding,
        sources: [finding.source],
        decoded: finding.decoded, // Preserve decoded JWT
      });
    } else {
      const existing = seen.get(key);
      // Track all unique sources in an array
      if (!existing.sources.includes(finding.source)) {
        existing.sources.push(finding.source);
      }
      // Keep the most specific pattern
      if (
        finding.pattern.includes("Google") &&
        !existing.pattern.includes("Google")
      ) {
        existing.pattern = finding.pattern;
        existing.description = finding.description;
      }
      // Keep decoded JWT if present
      if (finding.decoded && !existing.decoded) {
        existing.decoded = finding.decoded;
      }
    }
    return Array.from(seen.values());
  }, []);
}

// Function to copy findings to clipboard with LLM prompt
function copyToClipboard(findings) {
  // Scrub PII before creating the prompt
  const scrubbedFindings = scrubPII(findings);

  const prompt = `Hey boss, I need you to analyze a potential credential leak detected by **LeakAlert**, every vibe coder's fav Chrome extension.

Here's the leak finding as a JSON payload from LeakAlert:

${JSON.stringify(scrubbedFindings, null, 2)}

👉 I need you to help me figure out:
1. **What is this?**
2. **Why is it dangerous (if it is)?**
3. **How to spot FALSE POSITIVES and make sure they're not an issue?**
4. **If this is MY app:** what should I do to fix it, prevent it, and avoid embarrassing myself in the future?
5. **If this is SOMEONE ELSE'S app:** how do I report it responsibly without being a troll or breaking any laws?
6. **Explain like I'm a junior dev who didn't pay attention in school and now my life may be in your hands.**

DISCLAIMER: This is for **education**, **security awareness**, and **responsible development**. 
I even attempted to scrub the PII from the findings, but some sensitive information may still be present because I clearly don't know what I'm doing.
`;

  navigator.clipboard.writeText(prompt).then(() => {
    const btn = document.getElementById("copy-llm-btn");
    btn.textContent = "";
    btn.style.background = "#373d35";
    btn.style.marginBottom = "0";
    setTimeout(() => {
      btn.textContent = "";
    }, 2000);
  });
}

// Add PII scrubbing function
function scrubPII(findings) {
  const piiPatterns = {
    email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    phone: /(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g,
    ssn: /\b\d{3}[-]?\d{2}[-]?\d{4}\b/g,
    creditCard: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g,
    ipAddress: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
    name: /\b([A-Z][a-z]{1,15})\s([A-Z][a-z]{1,15})\b/g,
    address:
      /\d{1,5}\s\w+\s(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Circle|Cir|Place|Pl)\b/gi,
  };

  // Deep clone the findings to avoid modifying the original
  const scrubbedFindings = JSON.parse(JSON.stringify(findings));

  function scrubValue(str) {
    if (!str) return str;
    let result = str;

    // Replace each PII pattern with a redacted version
    for (const [type, pattern] of Object.entries(piiPatterns)) {
      result = result.replace(pattern, (match) => {
        // Keep first and last character for some context, redact middle
        if (type === "email") {
          const [local, domain] = match.split("@");
          return `${local[0]}***@${domain[0]}***${domain.slice(-4)}`;
        }
        if (match.length < 6) return "***";
        return `${match[0]}${"*".repeat(match.length - 2)}${
          match[match.length - 1]
        }`;
      });
    }
    return result;
  }

  // Recursively scrub all string values in the object
  function scrubObject(obj) {
    for (let key in obj) {
      if (typeof obj[key] === "string") {
        obj[key] = scrubValue(obj[key]);
      } else if (typeof obj[key] === "object" && obj[key] !== null) {
        scrubObject(obj[key]);
      }
    }
    return obj;
  }

  return scrubObject(scrubbedFindings);
}

// Original bookmarklet code - enhanced with additional functionality
function executeBookmarklet(settings = {}) {
  // Apply settings if provided
  if (Object.keys(settings).length > 0) {
    scanSettings = { ...scanSettings, ...settings };
  }

  console.log("Executing LeakAlert with settings:", scanSettings);

  // Reset findings array
  findings = [];

  // Sensitive patterns to scan for
  const sensitivePatterns = [
    // {
    //   label: "API Key",
    //   pattern: /api[_-]?key\s*[:=]\s*['"](AIza[0-9A-Za-z\-_]{35})['"]/gi,
    // },
    // {
    //   label: "Google API Key",
    //   pattern: /AIza[0-9A-Za-z\-_]{20,}/gi,
    //   description:
    //     "Google API keys (starting with AIza) can provide access to various Google services including Maps, YouTube, and Cloud APIs. If unrestricted, these can lead to unauthorized usage and billing charges.",
    // },
    {
      label: "Google OAuth Client ID",
      pattern:
        /client[_-]?id\s*[:=]\s*['"]([0-9]+-[0-9a-z]+\.apps\.googleusercontent\.com)['"]/gi,
    },
    {
      label: "Secret",
      pattern: /secret\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/gi,
    },
    { label: "Password", pattern: /password\s*[:=]\s*['"][^'"]{6,}['"]/gi },
    {
      label: "AWS Access Key ID",
      pattern: /aws_access_key_id\s*[:=]\s*['"]([A-Z0-9]{20})['"]/gi,
    },
    {
      label: "AWS Secret Access Key",
      pattern: /aws_secret_access_key\s*[:=]\s*['"]([A-Za-z0-9\/+=]{40})['"]/gi,
    },
    {
      label: "Authorization Bearer",
      pattern:
        /(authorization\s*[:=]\s*['"]Bearer\s+|Authorization:["']Bearer\s+)([A-Za-z0-9\-\._~\+\/]+=*)['"]/gi,
      description:
        "CRITICAL: Bearer tokens should never be exposed in client-side code. They provide direct API access with the permissions of the authenticated user and can be used to make unauthorized requests to your backend services.",
    },
    {
      label: "Private Key",
      pattern:
        /private[_-]?key\s*[:=]\s*['"]?-----BEGIN[ A-Z]+PRIVATE KEY-----[^-]+-----END[ A-Z]+PRIVATE KEY-----['"]?/is,
    },
    {
      label: "Client Secret",
      pattern: /client[_-]?secret\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['"]/gi,
    },
    // {
    //   label: "Firebase API Key",
    //   pattern:
    //     /firebase[_-]?api[_-]?key\s*[:=]\s*['"](AIza[0-9A-Za-z\-_]{35})['"]/gi,
    // },
    {
      label: "Stripe Publishable Key",
      pattern: /pk_(?:test|live)_[A-Za-z0-9]{24,}/gi,
      description:
        "Stripe publishable keys (pk_) are designed for client-side code and are generally safe to include in frontend code. However, they should be restricted to specific domains in your Stripe dashboard.",
    },
    {
      label: "Stripe Secret Key",
      pattern: /sk_(?:test|live)_[A-Za-z0-9]{24,}/gi,
      description:
        "CRITICAL: Stripe secret keys (sk_) should NEVER be exposed in client-side code. They provide full API access to your Stripe account, including the ability to create charges and access sensitive customer data.",
    },
    {
      label: "GitHub Token",
      pattern:
        /(github|gh)[_\-\.]?(?:token|key)\s*[:=]\s*['"]([a-zA-Z0-9_]{35,40})['"]/gi,
    },
    { label: "MongoDB URI", pattern: /mongodb(\+srv)?:\/\/[^\s"']+/gi },
    {
      label: "JWT Token",
      pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
      description:
        "JSON Web Token (JWT) found. These tokens often contain sensitive user data and authentication information. If exposed, they could be used to impersonate users or access protected resources.",
    },
    { label: "Slack Token", pattern: /xox[baprs]-[0-9a-zA-Z]{10,48}/gi },
    {
      label: "SendGrid API Key",
      pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/gi,
    },
    // {
    //   label: "Google API Key",
    //   pattern: /AIza[0-9A-Za-z\-_]{20,}/gi,
    //   description:
    //     "Google API keys (starting with AIza) can provide access to various Google services including Maps, YouTube, and Cloud APIs. If unrestricted, these can lead to unauthorized usage and billing charges.",
    // },
  ];

  // Enhanced false positive patterns
  const falsePositivePatterns = [
    /example/i,
    /sample/i,
    /test/i,
    /demo/i,
    /placeholder/i,
    /your[-_]?key[-_]?here/i,
    /your[-_]?token[-_]?here/i,
    /your[-_]?api[-_]?key/i,
    /your[-_]?secret/i,
    /your[-_]?password/i,
    /your[-_]?credentials/i,
    /replace[-_]?with[-_]?your/i,
    /insert[-_]?your/i,
    /change[-_]?this/i,

    // Framework-specific error codes and constants
    /wrong[-_]?password/i,
    /missing[-_]?password/i,
    /invalid[-_]?password/i,
    /incorrect[-_]?password/i,
    /password[-_]?incorrect/i,
    /password[-_]?mismatch/i,
    /password[-_]?required/i,
    /password[-_]?invalid/i,
    /password[-_]?error/i,
    /weak[-_]?password/i,
    /"password":\s*"(wrong|weak|missing|invalid)-password"/i,
    /"passwordError":/i,
    /"error":\s*"(wrong|weak|missing|invalid)-password"/i,
    /"code":\s*"auth\/(wrong|weak|missing|invalid)-password"/i,
    /"code":\s*"auth\/user-not-found"/i,

    // Next.js specific patterns
    /PASSWORD:['"](auth\/)?[a-z-]+-password['"]/i,
    /PASSWORD:['"](wrong|weak|missing|invalid)-password['"]/i,
    /PASSWORD:['"]auth\/[a-z-]+['"]/i,
    /CredentialsSignin:['"]\w+['"]/i,
  ];

  function isFalsePositive(text) {
    for (const pattern of falsePositivePatterns) {
      if (pattern.test(text)) {
        return true;
      }
    }

    const falsePositiveStrings = [
      "XXXX",
      "xxxx",
      "****",
      "0000",
      "AAAA",
      "aaaa",
      "ABCD",
      "abcd",
      "password",
      "Password",
      "PASSWORD",
      "apikey",
      "ApiKey",
      "APIKEY",
      "token",
      "Token",
      "TOKEN",
      "secret",
      "Secret",
      "SECRET",
      "key",
      "Key",
      "KEY",
      "username",
      "Username",
      "USERNAME",
      "user",
      "User",
      "USER",
      "login",
      "Login",
      "LOGIN",
      "credential",
      "Credential",
      "CREDENTIAL",
    ];

    if (falsePositiveStrings.includes(text)) {
      return true;
    }

    // Check for Next.js and Firebase specific error codes
    if (
      text.includes("wrong-password") ||
      text.includes("missing-password") ||
      text.includes("weak-password") ||
      text.includes("invalid-login") ||
      text.includes("CredentialsSignin")
    ) {
      return true;
    }

    // Check for Firebase Auth error codes
    if (
      text.includes("auth/wrong-password") ||
      text.includes("auth/weak-password") ||
      text.includes("auth/user-not-found") ||
      text.includes("auth/invalid-email") ||
      text.includes("auth/email-already-in-use") ||
      text.includes("auth/invalid-credential")
    ) {
      return true;
    }

    // Check for PASSWORD:"auth/..." pattern
    if (/PASSWORD:["']auth\/[a-z-]+["']/i.test(text)) {
      return true;
    }

    return false;
  }

  function scanText(content, source) {
    let found = false;
    sensitivePatterns.forEach(({ label, pattern, description }) => {
      // Reset pattern lastIndex to ensure consistent matching
      pattern.lastIndex = 0;

      let match;
      while ((match = pattern.exec(content)) !== null) {
        found = true;
        const fullMatch = match[0];
        const extractedValue = match[1] || fullMatch;
        const trimmed = fullMatch.trim();

        if (isFalsePositive(trimmed)) {
          console.info(`ℹ️ Ignored false positive in ${source}: ${trimmed}`);
          continue;
        }

        // Check if this exact match is already in findings to avoid duplicates
        const isDuplicate = findings.some(
          (f) =>
            f.source === source && f.match === trimmed && f.pattern === label
        );

        if (!isDuplicate) {
          findings.push({
            source,
            match: trimmed,
            extractedValue: extractedValue,
            pattern: label,
            description: description,
          });

          console.group(`🚨 Credentials found in ${source} [${label}]:`);
          console.warn(trimmed);
          if (description) {
            console.info(description);
          }
          console.groupEnd();
        }
      }
    });
    return found;
  }

  let leaks = 0;

  // Scan inline scripts if enabled
  if (scanSettings.scanInlineScripts) {
    const inlineScripts = Array.from(
      document.querySelectorAll("script:not([src])")
    );
    inlineScripts.forEach((script, index) => {
      if (scanText(script.textContent, `inline script #${index + 1}`)) {
        leaks++;
      }
    });
  }

  // Scan same-origin external scripts if enabled
  if (scanSettings.scanExternalScripts) {
    const externalScripts = Array.from(
      document.querySelectorAll("script[src]")
    ).filter((script) => {
      try {
        return new URL(script.src, location.href).origin === location.origin;
      } catch (e) {
        console.warn(`❗ Invalid script URL: ${script.src}`);
        return false;
      }
    });

    const fetches = externalScripts.map((script) => {
      return fetch(script.src)
        .then((res) => res.text())
        .then((js) => {
          if (scanText(js, `external script (${script.src})`)) {
            leaks++;
          }
        })
        .catch((error) => {
          console.warn(`❗ Could not fetch ${script.src}: ${error.message}`);
        });
    });

    // Wait for all fetches to complete
    Promise.all(fetches.map((p) => p.catch((e) => e))).then(() => {
      handleScanCompletion();
    });
  } else if (!scanSettings.scanWindowObjects) {
    // If we're not scanning window objects and not scanning external scripts,
    // we can complete the scan immediately
    handleScanCompletion();
  }

  // Scan for credentials in window objects
  function scanWindowObjects() {
    const windowObjectPatterns = [
      // {
      //   pattern: "Google API Key",
      //   regex: /AIza[0-9A-Za-z_-]{20,}/,
      //   description:
      //     "Used for Google Maps, YouTube, Firebase and other Google Cloud services. If unrestricted, could lead to unauthorized usage and billing charges.",
      // },
      {
        pattern: "AWS Access Key",
        regex: /AKIA[0-9A-Z]{16}/,
        description:
          "Provides access to AWS services and infrastructure. High security risk that could lead to account compromise or cloud resource abuse.",
      },
      {
        pattern: "Stripe API Key",
        regex: /(pk|sk)_(test|live)_[0-9a-zA-Z]{24}/,
        description:
          "Used for payment processing. Live keys can have direct financial impact if exposed.",
      },
      {
        pattern: "GitHub Token",
        regex: /(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}/,
        description:
          "Provides access to GitHub repositories and APIs. Could expose source code and intellectual property.",
      },
      {
        pattern: "OpenAI API Key",
        regex: /sk-[a-zA-Z0-9]{48}/,
        description:
          "Used for AI services like ChatGPT. Could result in unauthorized usage and significant charges.",
      },
      // {
      //   pattern: "Firebase API Key",
      //   regex: /AIza[0-9A-Za-z_-]{35}/,
      //   description:
      //     "Used for Firebase services. Similar to Google API keys, may allow access to your Firebase project.",
      // },
      {
        pattern: "Twilio API Key",
        regex: /SK[0-9a-fA-F]{32}/,
        description:
          "Used for messaging and communication services. Could allow sending messages on your behalf.",
      },
      {
        pattern: "SendGrid API Key",
        regex: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/,
        description:
          "Used for email delivery services. Could allow sending emails from your account.",
      },
      {
        pattern: "JWT Token",
        regex: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/,
        description:
          "Authentication token that may contain sensitive user data and session information.",
      },
      {
        pattern: "Bearer Token",
        regex: /bearer [a-zA-Z0-9_\-.~+\/]+=*$/i,
        description:
          "Used for API authentication. May provide access to protected resources and user data.",
      },
      {
        pattern: "MongoDB Connection String",
        regex: /mongodb(\+srv)?:\/\/[^\s"']+/,
        description:
          "Database connection string that provides direct access to your MongoDB database.",
      },
      {
        pattern: "MySQL Connection String",
        regex: /mysql:\/\/[^\s"']+/,
        description:
          "Database connection string that provides direct access to your MySQL database.",
      },
      {
        pattern: "PostgreSQL Connection String",
        regex: /postgres(ql)?:\/\/[^\s"']+/,
        description:
          "Database connection string that provides direct access to your PostgreSQL database.",
      },
      {
        pattern: "Password",
        regex: /password['":\s]*[=:]\s*['"]([^'"]{4,})['"]/,
        description:
          "Plain text password found in code. Serious security risk.",
      },
      {
        pattern: "API Key",
        regex: /api[_-]?key['":\s]*[=:]\s*['"]([^'"]{5,})['"]/,
        description:
          "Generic API key that may provide access to various services.",
      },
      {
        pattern: "Secret Key",
        regex: /secret[_-]?key['":\s]*[=:]\s*['"]([^'"]{5,})['"]/,
        description:
          "Secret key that may be used for encryption or authentication.",
      },
      {
        pattern: "Access Token",
        regex: /access[_-]?token['":\s]*[=:]\s*['"]([^'"]{5,})['"]/,
        description:
          "Token used for API access. May provide access to protected resources.",
      },
      {
        pattern: "Auth Token",
        regex: /auth[_-]?token['":\s]*[=:]\s*['"]([^'"]{5,})['"]/,
        description:
          "Authentication token that may provide access to user accounts or protected resources.",
      },
    ];

    const visited = new Set();

    function scanObject(obj, path = "window", depth = 0) {
      // Limit recursion depth to avoid stack overflow
      if (depth > 5 || visited.has(obj)) return;
      visited.add(obj);

      if (typeof obj === "string") {
        windowObjectPatterns.forEach(({ pattern, regex, description }) => {
          const match = regex.exec(obj);
          if (match) {
            const trimmed = match[0].trim();
            if (isFalsePositive(trimmed)) {
              console.info(`ℹ️ Ignored false positive in ${path}: ${trimmed}`);
              return;
            }

            // Check if this exact match is already in findings to avoid duplicates
            const isDuplicate = findings.some(
              (f) =>
                f.source === path &&
                f.match === trimmed &&
                f.pattern === pattern
            );

            if (!isDuplicate) {
              findings.push({
                source: path,
                match: trimmed,
                pattern: pattern,
                description: description,
              });

              console.group(`🚨 Credentials found in ${path} [${pattern}]:`);
              console.warn(trimmed);
              console.groupEnd();
            }
          }
        });
      } else if (typeof obj === "object" && obj !== null) {
        for (const key in obj) {
          if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;

          // Skip DOM nodes and functions
          if (obj[key] instanceof Node || typeof obj[key] === "function")
            continue;

          try {
            scanObject(obj[key], `${path}.${key}`, depth + 1);
          } catch (e) {
            // Silently ignore errors accessing properties
          }
        }
      }
    }

    // Start scanning window object with a timeout to not block the UI
    setTimeout(() => {
      try {
        scanObject(window);
      } catch (e) {
        console.error("Error scanning window object:", e);
      }

      // Complete the scan if external scripts are not being scanned
      if (!scanSettings.scanExternalScripts) {
        handleScanCompletion();
      }
    }, 0);
  }

  // Recursive scan of window object properties if enabled
  if (scanSettings.scanWindowObjects) {
    scanWindowObjects();
  }

  // Process JWT tokens for display
  function processJWT(finding) {
    if (finding.pattern === "JWT Token" && finding.match) {
      try {
        const jwtParts = finding.match.split(".");
        if (jwtParts.length === 3) {
          try {
            const header = JSON.parse(atob(jwtParts[0]));
            const payload = JSON.parse(atob(jwtParts[1]));

            finding.decoded = {
              header: header,
              payload: payload,
              signature: jwtParts[2], // Can't decode the signature
            };

            // Add expiration info
            if (payload.exp) {
              const expDate = new Date(payload.exp * 1000);
              finding.description =
                (finding.description || "") +
                ` Expires: ${expDate.toLocaleString()}.`;
            }

            // Add issuer info
            if (payload.iss) {
              finding.description =
                (finding.description || "") + ` Issuer: ${payload.iss}.`;
            }

            // Check for sensitive data
            if (payload.email || payload.sub || payload.name) {
              finding.description =
                (finding.description || "") +
                " Contains personally identifiable information.";
            }
          } catch (e) {
            console.warn("Error decoding JWT:", e);
          }
        }
      } catch (e) {
        console.warn("Error processing JWT:", e);
      }
    }
    return finding;
  }

  // Handle scan completion and show results
  function handleScanCompletion() {
    if (findings.length > 0) {
      // First deduplicate findings
      findings = dedupFindings(findings);

      // Then process any JWT tokens
      findings = findings.map((finding) => {
        if (finding.pattern === "JWT Token" && finding.match) {
          return processJWT(finding);
        }
        return finding;
      });

      if (scanSettings.showPopupOnScan) {
        showPopup(findings);
      }
    } else {
      console.log("✅ No obvious credential leaks found.");
    }
  }

  // Download findings as a JSON file
  function exportFindings(data, filename = "credential-findings.json") {
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    console.info(`📦 Findings exported as ${filename}`);
  }

  // Copy findings to clipboard with fallback
  function copyFindingsToClipboard(data) {
    const text = JSON.stringify(data, null, 2);
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard
        .writeText(text)
        .then(() => {
          console.info("📋 Findings copied to clipboard");
        })
        .catch((err) => {
          console.warn(
            "❌ Clipboard write failed, using prompt fallback:",
            err
          );
          fallbackCopy(text);
        });
    } else {
      fallbackCopy(text);
    }
  }

  function fallbackCopy(text) {
    const promptMsg =
      "⚠️ Clipboard access not available.\nPlease copy the findings manually.";
    window.prompt(promptMsg, text);
  }

  // UI Popup Display + Validate Button
  function showPopup(data) {
    const existingPopup = document.getElementById("scanner-popup");
    if (existingPopup) existingPopup.remove();

    const popup = document.createElement("div");
    popup.id = "scanner-popup";
    popup.style.cssText = `
      position: fixed; top: 10px; right: 10px; z-index: 999999;
      width: 450px; background: #111; color: #fff; border-radius: 8px;
      box-shadow: 0 0 10px rgba(0,0,0,0.5); padding: 20px;
      font-family: system-ui, arial, sans-serif; font-size: 14px; font-weight: 400; 
    `;

    // Append to body first to ensure it exists before adding event listeners
    document.body.appendChild(popup);

    const findingsHTML = data.map(item => {
      return `
        <div style="margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid #333;">
          <div style="margin-bottom: 5px; color: #fff;"><strong style='color: #fff;'>Type:</strong> ${item.pattern}</div>
          <div style="margin-bottom: 5px; color: #fff;">
            <strong style='color: #fff;'>Found in ${item.sources.length} location${item.sources.length > 1 ? "s" : ""}:</strong>
            <ul style="margin: 5px 0; padding-left: 20px; list-style-type: disc;">
              ${item.sources.map(source => `<li style="color: #ffa07a;font-weight: 400;font-family: system-ui, arial, sans-serif; font-size: 14px;">${source}</li>`).join("")}
            </ul>
          </div>
          <div style="margin-bottom: 5px; color: #fff;"><strong style='color: #fff;'>Match:</strong> <code style="word-break: break-all;color: #fdf3aa;font-weight: bold;font-family: monospace; background: #23232b; font-size: 14px; border: none; padding: 2px 6px; border-radius: 4px;">${item.match}</code></div>
          ${item.description ? `<div style="margin-bottom: 5px; color: #fff;"><strong style='color: #fff;'>Description:</strong> ${item.description}</div>` : ""}
          ${item.decoded ? `
            <div style="margin-top: 5px; color: #fff;">
              <strong style='color: #fff;'>Decoded:</strong>
              <pre style="margin: 5px 0; padding: 5px; background: #222; border-radius: 3px; overflow-x: auto; white-space: pre-wrap; word-break: break-all;color: #fdf3aa;font-weight: bold;font-family: monospace;">${JSON.stringify(item.decoded, null, 2)}</pre>
            </div>
          ` : ""}
        </div>
      `;
    }).join("");

    popup.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
        <h3 style="margin: 0 0 5px; font-size: 17px; color: white; padding: 0; font-weight: 400; font-family: system-ui, arial, sans-serif;">🚨 Leaks Found</h3>
        <span id="close-popup-btn" style="cursor: pointer; font-size: 18px; color: #ffa07a">✖</span>
      </div>
      <p style="margin-bottom: 10px; font-size: 14px; font-weight: 400; font-family: system-ui, arial, sans-serif; color: #fff;">
        ${data.length} potential leak${data.length !== 1 ? "s" : ""} detected
        <button id="copy-llm-btn" style="float: right; background: #373d35; color: #fdf3aa; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; font-family: system-ui, arial, sans-serif; font-weight: 600;"></button>
      </p>
      <div style="max-height: 300px; overflow-y: auto; margin-bottom: 15px; border: 1px solid #333; padding: 10px; border-radius: 4px;">
        ${findingsHTML}
      </div>
      <button id="export-btn" style="font-family: system-ui, arial, sans-serif !important; font-size: 15px;font-weight: 600;padding: 16px 8px;line-height:0;margin-bottom:8px;margin-left:auto;margin-right:auto;width:100%;padding:16px 8px;background:#373d35;color:white;border:none;border-radius:4px;cursor:pointer;transition: 0.1s background linear;">
        📦 Export Findings
      </button>
      <button id="copy-btn" style="font-family: system-ui, arial, sans-serif !important; font-size: 15px;font-weight: 600;padding: 16px 8px;line-height:0;margin-bottom:8px;margin-left:auto;margin-right:auto;width:100%;padding:16px 8px;background:#373d35;color:white;border:none;border-radius:4px;cursor:pointer;transition: 0.1s background linear;">
        📋 Copy to Clipboard
      </button>
      <style>
        #scanner-popup button:hover {
          background: #1b211a !important;
          transition: 0.1s background linear;
        }
      </style>
    `;

    // Add event listeners
    const closeBtn = document.getElementById("close-popup-btn");
    const copyLLMBtn = document.getElementById("copy-llm-btn");
    const exportBtn = document.getElementById("export-btn");
    const copyBtn = document.getElementById("copy-btn");

    if (closeBtn) {
      closeBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        popup.remove();
      });
    }

    if (copyLLMBtn) {
      copyLLMBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        copyToClipboard(data);
      });
    }

    if (exportBtn) {
      exportBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        exportFindings(data);
      });
    }

    if (copyBtn) {
      copyBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        copyFindingsToClipboard(data);
      });
    }

    // Prevent popup from disappearing when clicking inside it
    popup.addEventListener("click", (e) => {
      e.stopPropagation();
    });
  }
}

// Execute the bookmarklet code when the content script is injected
executeBookmarklet();

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "execute") {
    executeBookmarklet(request.settings);
    sendResponse({ status: "executed", results: findings });
    return true;
  }

  if (request.action === "export") {
    // Export findings as a JSON file
    const blob = new Blob([JSON.stringify(request.data, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = request.filename || "credential-findings.json";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    sendResponse({ status: "exported" });
    return true;
  }

  return false;
});
