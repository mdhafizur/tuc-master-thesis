// SQL injection in user login
// CWE: CWE-89
// Severity: high
// Source: OWASP Juice Shop

// From OWASP Juice Shop - Login bypass
const user = models.User.findOne({
  where: {
    email: req.body.email,
    password: security.hash(req.body.password)
  }
});