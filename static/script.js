document.addEventListener('DOMContentLoaded', () => {

    const cveInput = document.getElementById('cve-input');
    const searchButton = document.getElementById('search-button');
    const resultsContainer = document.getElementById('results-container');
    const publicationsContainer = document.getElementById('publications-container');

    // --- 1. Handle CVE Search (UPDATED) ---
    async function searchProtections() {
        const cveId = cveInput.value.trim();
        if (!cveId) {
            resultsContainer.innerHTML = '<p style="color: red;">Please enter a CVE ID.</p>';
            return;
        }

        resultsContainer.innerHTML = '<p class="loading">Searching...</p>';

        try {
            const response = await fetch(`/protections?cve_id=${encodeURIComponent(cveId)}`);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to fetch protections.');
            }
            
            resultsContainer.innerHTML = '<h3>Search Results</h3>';

            // Helper function for escaping HTML
            const escapeHTML = (str) => str ? str.replace(/[&<>"']/g, match => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            }[match])) : '';

            if (!Array.isArray(data) || data.length === 0) {
                resultsContainer.innerHTML += '<p>No protections found for this CVE.</p>';
                const escapedCveId = escapeHTML(cveId);
                const url = `https://nvd.nist.gov/vuln/detail/${escapedCveId}`;
                resultsContainer.innerHTML += `<p>For more information, see <a href="${url}" target="_blank" rel="noopener noreferrer">${escapedCveId}</a></p>`;
                return;
            }

            data.forEach(item => {
                
                // Get and apply severity
                const severity = escapeHTML(item.severity_level) || 'N/A';
                const severityClass = severity ? `advisory-severity-${severity.toLowerCase()}` : '';

                // --- 🚨 NEW ROBUST CVE ARRAY HANDLING ---
                let cveArray = []; // Start with an empty array
                if (Array.isArray(item.cve)) {
                    // It's already an array, use it
                    cveArray = item.cve;
                } else if (item.cve) {
                    // It's something else (like a string), wrap it in an array
                    cveArray = [item.cve];
                }
                // Now cveArray is guaranteed to be an array, so .map() will work
                // --- END NEW LOGIC ---

                // Build CVE links
                const cveLinks = cveArray.map(cveId => {
                    const escapedCveId = escapeHTML(cveId);
                    const url = `https://nvd.nist.gov/vuln/detail/${escapedCveId}`;
                    return `<a href="${url}" target="_blank" rel="noopener noreferrer">${escapedCveId}</a>`;
                }).join(', ');

                // Build the HTML card
                const cardHTML = `
                    <div class="result-card">
                        <h4>${escapeHTML(item.protection_name)}</h4>
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
            searchProtections();
        }
    });

    // --- 2. Load Publications on Page Load ---
    async function loadPublications() {
        try {
            const response = await fetch('/publications');
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to fetch publications.');
            }
            
            const publications = data.publications || data;
            
            if (!Array.isArray(publications) || publications.length === 0) {
                publicationsContainer.innerHTML = '<p>No publications found.</p>';
                return;
            }

            let table = '<table><thead><tr><th>Release Version</th><th>Package Version</th><th>Released Date</th></tr></thead><tbody>';
            
            for (const item of publications) {
                const releaseVersion = item.release_version || 'N/A';
                const packageVersion = item.package_version || 'N/A';
                const releasedDate = item.released_date || 'N/A';
                
                table += `<tr><td>${releaseVersion}</td><td>${packageVersion}</td><td>${releasedDate}</td></tr>`;
            }
            
            table += '</tbody></table>';
            publicationsContainer.innerHTML = table;

        } catch (error) {
            publicationsContainer.innerHTML = `<p style="color: red;">Error: ${error.message}</p>`;
        }
    }

    // Run the function to load publications
    loadPublications();
});
