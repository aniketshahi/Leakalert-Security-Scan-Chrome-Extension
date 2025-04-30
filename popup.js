/**
 * Popup script for LeakAlert
 * A powerful credential scanner for the web
 */

document.addEventListener("DOMContentLoaded", () => {
  // Tab navigation
  const tabs = document.querySelectorAll(".tab");
  const tabContents = document.querySelectorAll(".tab-content");
  const resultsContainer = document.getElementById("resultsContainer");

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      // Remove active class from all tabs and contents
      tabs.forEach((t) => t.classList.remove("active"));
      tabContents.forEach((c) => c.classList.remove("active"));

      // Add active class to clicked tab and corresponding content
      const tabName = tab.getAttribute("data-tab");
      tab.classList.add("active");
      document.getElementById(tabName).classList.add("active");
    });
  });

  // Buttons and status elements
  const executeButton = document.getElementById("executeButton");
  const scanStatus = document.getElementById("scanStatus");

  // Track if a scan has ever completed
  let hasScanned = false;

  // Settings checkboxes
  const scanInlineScripts = document.getElementById("scanInlineScripts");
  const scanExternalScripts = document.getElementById("scanExternalScripts");
  const scanWindowObjects = document.getElementById("scanWindowObjects");
  const showPopupOnScan = document.getElementById("showPopupOnScan");

  // Load saved settings
  chrome.storage.sync.get({
    scanInlineScripts: true,
    scanExternalScripts: true,
    scanWindowObjects: true,
    showPopupOnScan: true
  }, (items) => {
    scanInlineScripts.checked = items.scanInlineScripts;
    scanExternalScripts.checked = items.scanExternalScripts;
    scanWindowObjects.checked = items.scanWindowObjects;
    showPopupOnScan.checked = items.showPopupOnScan;
  });

  // Save settings when changed
  [scanInlineScripts, scanExternalScripts, scanWindowObjects, showPopupOnScan].forEach(checkbox => {
    checkbox.addEventListener("change", () => {
      chrome.storage.sync.set({
        scanInlineScripts: scanInlineScripts.checked,
        scanExternalScripts: scanExternalScripts.checked,
        scanWindowObjects: scanWindowObjects.checked,
        showPopupOnScan: showPopupOnScan.checked
      });
    });
  });

  // Update scan status with styling
  const updateScanStatus = (message, type = 'scanning') => {
    scanStatus.style.display = 'block';
    scanStatus.textContent = message;
    scanStatus.className = type;

    if (type === "success") {
      hasScanned = true;
      executeButton.style.display = "block";
      executeButton.disabled = false;
      executeButton.textContent = "Rescan";
    } else if (type === "scanning") {
      executeButton.disabled = true;
      executeButton.textContent = "Scanning...";
    } else {
      executeButton.style.display = "block";
      executeButton.disabled = false;
      executeButton.textContent = hasScanned ? "Rescan" : "Run Security Scan";
    }
  };

  // Update scan stats
  function updateScanStats() {
    chrome.storage.local.get(['leakalert_lastScan', 'leakalert_issuesFound'], (data) => {
      // Format time
      let lastScanText = "Never";
      if (data.leakalert_lastScan) {
        const diff = Math.floor((Date.now() - data.leakalert_lastScan) / 60000);
        lastScanText = diff === 0 ? "Just now" : `${diff}m ago`;
      }
      const lastScanElem = document.getElementById("lastScanTime");
      if (lastScanElem) lastScanElem.textContent = lastScanText;
      const issuesElem = document.getElementById("issuesFound");
      if (issuesElem) issuesElem.textContent = data.leakalert_issuesFound || 0;
    });
  }

  updateScanStats();

  // Function to display scan results
  const displayResults = (results) => {
    let summaryHtml = '';
    if (!results || results.length === 0) {
      summaryHtml = `
        <div class="result-item">
          <div class="result-label">No issues found</div>
          <p>Great news! No potential credential leaks were detected.</p>
        </div>
      `;
    } else {
      summaryHtml = `
        <div class="result-item">
          <div class="result-label">Scan Summary</div>
          <p><strong>${results.length} issue${results.length === 1 ? '' : 's'} found.</strong></p>
        </div>
      `;
      summaryHtml += results.map((result, index) => `
        <div class="result-item">
          <div class="result-label">${result.type || result.pattern}</div>
          <div class="result-value">${result.value || result.match}</div>
          ${result.location ? `<div class="result-location">Found in: ${result.location}</div>` : ''}
        </div>
      `).join('');
    }
    resultsContainer.innerHTML = summaryHtml;
  };

  // Execute scan button
  executeButton.addEventListener("click", () => {
    updateScanStatus("🔄 Refreshing page and preparing scan...", "scanning");
    executeButton.disabled = true;
    executeButton.textContent = "Scanning...";

    // Execute the scan in the current tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0]) {
        // First refresh the page
        chrome.tabs.reload(tabs[0].id, {}, () => {
          // Wait for the page to load before scanning
          setTimeout(() => {
            chrome.tabs.sendMessage(
              tabs[0].id,
              {
                action: "execute",
                settings: {
                  scanInlineScripts: scanInlineScripts.checked,
                  scanExternalScripts: scanExternalScripts.checked,
                  scanWindowObjects: scanWindowObjects.checked,
                  showPopupOnScan: showPopupOnScan.checked
                },
              },
              (response) => {
                if (chrome.runtime.lastError) {
                  console.error(chrome.runtime.lastError);
                  updateScanStatus("❌ Error: Content script not ready. Please try again.", "error");
                } else {
                  updateScanStatus("✅ Scan completed successfully!", "success");
                  // Save scan stats
                  const issuesCount = response && (response.results ? response.results.length : (response.findings ? response.findings.length : 0));
                  chrome.storage.local.set({
                    leakalert_lastScan: Date.now(),
                    leakalert_issuesFound: issuesCount
                  }, updateScanStats);
                  // Always switch to results tab and show summary
                  tabs.forEach(t => t.classList.remove("active"));
                  tabContents.forEach(c => c.classList.remove("active"));
                  document.querySelector('[data-tab="results"]').classList.add("active");
                  document.getElementById("results").classList.add("active");
                  // Display results summary
                  const resultsArr = response.results || response.findings || [];
                  displayResults(resultsArr);
                }
              }
            );
          }, 1500); // Give the page 1.5 seconds to load
        });
      } else {
        updateScanStatus("❌ Error: No active tab found", "error");
        executeButton.disabled = false;
        executeButton.textContent = "Run Security Scan";
      }
    });
  });
});
