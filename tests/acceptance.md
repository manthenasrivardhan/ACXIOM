# Acceptance Test Plan

1. Anonymous request to `/api/dashboard` returns 401.
2. Admin login succeeds and sets a session cookie.
3. Invalid login is rejected.
4. Five invalid passwords trigger temporary lockout.
5. Admin can access Users & Roles.
6. Sales Executive cannot access Admin user management.
7. Customer creation validates email and duplicate email.
8. Lead creation supports New/Contacted/Qualified/Unqualified/Converted/Lost.
9. Lead conversion creates a customer and changes lead status to Converted.
10. Opportunity rejects amount <= 0.
11. Opportunity rejects probability outside 0-100.
12. Active opportunity rejects a past expected-close date.
13. Weighted pipeline equals Amount * Probability / 100.
14. Planned follow-up rejects a past date.
15. Audit log records login/logout/create/update/delete/convert actions.
16. Dashboard counts change after creating CRM records.
17. `/docs` exposes the REST API documentation.
