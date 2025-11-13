document.addEventListener('DOMContentLoaded', () => {

    const cveInput = document.getElementById('cve-input');
    const searchButton = document.getElementById('search-button');
    const resultsContainer = document.getElementById('results-container');
    
    // Target the div inside <details>
    const statusContainer = document.getElementById('status-container'); 
    // Target the new <summary> ID
    const statusSummaryLine = document.getElementById('status-summary-line'); 

    // Helper function for escaping HTML
    const escapeHTML = (str) => str ? str.replace(/[&<>"']/g, match => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[match])) : '';

    // Helper function for localizing time
    function formatDateForDisplay(isoString) {
        if (!isoString || isoString === 'N/A') return 'N/A';
        
        try {
            const date = new Date(isoString);
            
            // Use browser's locale and options for a friendly format
            return date.toLocaleTimeString(navigator.language, {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                timeZoneName: 'short'
            });
        } catch (e) {
            console.error("Error formatting date:", e);
            return isoString; // Fallback to the original raw string
        }
    }


    // --- 1. Handle CVE Search (MODIFIED FOR MULTI-CVE) ---
    async function searchProtections() {
        // 🚨 NEW: Input Parsing Logic
        const rawInput = cveInput.value.trim();
        resultsContainer.innerHTML = ''; // Clear previous results

        if (!rawInput) {
            resultsContainer.innerHTML = '<p style="color: red;">Please enter one or more CVE IDs.</p>';
            return;
        }
        
        // Split by comma, space, or a combination
        const cveInputs = rawInput.split(/[,\s]+/);
        const validCveIds = [];
        const invalidCveIds = [];
        
        // RegEx for validation
        const cvePattern = /^(?:CVE-)?(\d{4})-(\d{3,6})$/i; 

        cveInputs.forEach(input => {
            const trimmedInput = input.trim();
            if (!trimmedInput) return; // Skip empty strings
            
            const match = trimmedInput.match(cvePattern);

            if (match) {
                // It's a valid CVE format
                let normalizedCve = trimmedInput.toUpperCase();
                if (!normalizedCve.startsWith('CVE-')) {
                    normalizedCve = `CVE-${normalizedCve}`;
                }
                validCveIds.push(normalizedCve);
            } else {
                // It's an invalid format
                invalidCveIds.push(trimmedInput);
            }
        });

        // 🚨 NEW: Handle Validation Results
        if (validCveIds.length === 0) {
            resultsContainer.innerHTML = `<p style="color: red;">No valid CVE IDs found. Invalid formats: ${invalidCveIds.join(', ')}</p>`;
            return;
        }
        
        resultsContainer.innerHTML = `<p class="loading">Searching for ${validCveIds.length} CVE(s)...</p>`;

        // Show invalid entries as a warning if some were valid
        if (invalidCveIds.length > 0) {
            resultsContainer.innerHTML += `<p style="color: orange; font-size: 14px;">(Skipped invalid inputs: ${invalidCveIds.join(', ')})</p>`;
        }
        
        // --- End New Parsing Logic ---

        try {
            // 🚨 NEW: Send POST request with JSON body (array of CVEs)
            const response = await fetch(`/protections`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ cve_ids: validCveIds }) // Send the array
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to fetch protections.');
            }
            
            resultsContainer.innerHTML += '<h3>Search Results</h3>';

            if (!Array.isArray(data) || data.length === 0) {
                resultsContainer.innerHTML += '<p>No protections found for the specified CVE(s).</p>';
                return;
            }

            data.forEach(item => {
                
                const severity = escapeHTML(item.severity_level) || 'N/A';
                const severityClass = severity ? `advisory-severity-${severity.toLowerCase()}` : '';

                let cveArray = []; 
                if (Array.isArray(item.cve)) {
                    cveArray = item.cve;
                } else if (item.cve) {
                    cveArray = [item.cve];
                }

                const cveLinks = cveArray.map(cveId => {
                    const escapedCveId = escapeHTML(cveId);
                    const url = `https://nvd.nist.gov/vuln/detail/${escapedCveId}`;
                    return `<a href="${url}" target="_blank" rel="noopener noreferrer">${escapedCveId}</a>`;
                }).join(', ');

                const cardHTML = `
                    <div class="result-card">
                        <h4>${escapeHTML(item.protection_name)}</h4>
                        <p><strong>Source:</strong> ${escapeHTML(item.source_label || 'N/A')}</p> 
                        <p><strong>Severity:</strong> <span class="${severityClass}">${severity}</span></p>
                        <p><strong>Confidence:</strong> ${escapeHTML(item.confidence_level)}</p>
                        <p><strong>Description:</strong> ${escapeHTML(item.protection_description)}</p>
                        <p><strong>Advisory:</strong> <a href="${escapeHTML(item.protection_advisory_url)}" target="_blank" rel="noopener noreferrer">${escapeHTML(item.protection_advisory_url)}</a></p>
                        <p><strong>Covered CVEs:</strong> <span class="cve-list">${cveLinks || 'N/A'}</span></p> 
                        <p><strong>Vulnerable Systems:</strong></p>
                        <div class="vuln-systems">${escapeHTML(item.vulnerable_systems)}</div>
                    </div>
                `;
                resultsContainer.innerHTML += cardHTML;
            });

        } catch (error) {
            resultsContainer.innerHTML = `<p style="color: red;">Error: ${error.message}</p>`;
        }
    }

    searchButton.addEventListener('click', searchProtections);
    
    cveInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
            searchProteCTIONS(); // Typo in original file, fixed to searchProtections
        }
    });

    // --- 2. Load Combined API Status ---
    async function loadApiStatus() {
        if (!statusContainer || !statusSummaryLine) return;

        try {
            statusSummaryLine.innerHTML = '<p class="loading" style="display: inline;">Loading configuration status...</p>';
            
            const response = await fetch('/api_status');
            const data = await response.json();

            if (!response.ok) {
                throw new Error("Failed to fetch API status.");
            }
            
            // --- Configuration Summary (Always Visible and Clickable) ---
            const primaryEnabled = data.primary_enabled;
            const secondaryEnabled = data.secondary_enabled;

            const finalConfigSummaryHTML = `
                <strong>Configuration Status:</strong> 
                Infinity Portal: <span style="color: ${primaryEnabled ? 'green' : 'red'};">${primaryEnabled ? 'Enabled' : 'Disabled'}</span> | 
                Smart-1 Cloud: <span style="color: ${secondaryEnabled ? 'green' : 'red'};">${secondaryEnabled ? 'Enabled' : 'Disabled'}</span>
            `;
            // FIX: Inject the HTML directly into the <summary> element
            statusSummaryLine.innerHTML = finalConfigSummaryHTML;


            // --- Build Detailed Status Contents (for the collapsible part) ---
            statusContainer.innerHTML = ''; 
            let combinedHTML = '';
            
            // --- A. Render Secondary (S1C IPS Status - Inline Block Format) ---
            if (data.ips_status) {
                const status = data.ips_status;
                
                const updateColor = status.update_available ? 'red' : 'green';
                const updateStatus = status.update_available ? 'Update Available' : 'Current';
                const formattedUpdateTime = formatDateForDisplay(status.last_updated_time);

                const s1cStatusBlock = `
                    <div class="status-content" style="padding-top: 10px; margin-bottom: 10px;">
                        <h3 style="margin-top: 5px; margin-bottom: 8px;">Smart-1 Cloud IPS Database Status</h3>
                        
                        <div style="font-size: 14px; padding: 5px 0;">
                            <strong>Installed Version:</strong> ${escapeHTML(status.installed_version || 'N/A')} 
                            | <strong>Released Date:</strong> ${formattedUpdateTime} 
                            | <strong>Status:</strong> <span style="color: ${updateColor}; font-weight: bold;">${updateStatus}</span>
                        </div>
                    </div>
                `;
                combinedHTML += s1cStatusBlock;

            } else if (secondaryEnabled) {
                combinedHTML += `<p style="color: orange;">Smart-1 Cloud Status: ${data.secondary_status}</p>`;
            } 

            // --- B. Render Primary (Publications Block - Inline Block Format) ---
            if (data.publications && Array.isArray(data.publications) && data.publications.length > 0) {
                
                let publicationsHTML = `
                    <div id="publications-container" style="margin-top: 15px;">
                        <h3 style="margin-top: 5px; margin-bottom: 8px;">Latest IPS Publications</h3>
                `;
                
                const latestPublication = data.publications[0];
                const releaseVersion = escapeHTML(latestPublication.release_version || 'N/A');
                const packageVersion = escapeHTML(latestPublication.package_version || 'N/A');
                const releasedDate = escapeHTML(latestPublication.released_date || 'N/A');
                
                const formattedReleaseDate = formatDateForDisplay(releasedDate);

                publicationsHTML += `
                    <div style="font-size: 14px; padding: 5px 0;">
                        <strong>Release:</strong> ${releaseVersion}
                        | <strong>Package Version:</strong> ${packageVersion}
                        | <strong>Released Date:</strong> ${formattedReleaseDate}
                    </div>
                `;
                
                publicationsHTML += '</div>';
                combinedHTML += publicationsHTML;

            } else if (primaryEnabled) {
                 combinedHTML += `<p style="color: orange; margin-top: 10px;">IPS Publications Status: ${data.primary_status}</p>`;
            }
            
            // Finalize detailed display
            if (combinedHTML) {
                statusContainer.innerHTML = combinedHTML;
            } else {
                statusContainer.innerHTML = '<p>No detailed status available.</p>';
            }


        } catch (error) {
            statusSummaryLine.innerHTML = `<p style="color: red;">Error fetching API status.</p>`;
            statusContainer.innerHTML = `<p style="color: red;">Detailed Error: ${error.message}</p>`;
        }
    }

    // Run the function to load status
    loadApiStatus();
});
