// DOM-based XSS in search
// CWE: CWE-79
// Severity: medium
// Source: OWASP Juice Shop

// From OWASP Juice Shop - Search functionality
function search() {
  const searchValue = $('#searchQuery').val();
  $('#searchResult').html('<h3>Results for "' + searchValue + '"</h3>');
}