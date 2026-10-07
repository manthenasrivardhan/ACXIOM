# AcxiomCRM - Python Complete Edition

## Structure

```text
AcxiomCRM_Python_FINAL/
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   └── acxiomcrm.db       # generated at runtime
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── database/
├── tests/
├── README.md
├── .gitignore
└── run_windows.bat
```

## Run

```cmd
cd backend
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app:app --reload
```

Open:

http://127.0.0.1:8000

API documentation:

http://127.0.0.1:8000/docs

## Demo users

Admin:
`admin@acxiomcrm.local` / `Admin@123`

Manager:
`manager@acxiomcrm.local` / `Manager@123`

Sales Executive:
`sales@acxiomcrm.local` / `Sales@123`

## Included functionality

- Authentication and logout
- HTTP-only session cookie
- scrypt password hashing
- Account lockout after repeated failures
- Admin/Manager/Sales Executive RBAC
- Customer create/search/update/delete API
- Lead create/update/list and conversion
- Opportunity create/update/delete and weighted pipeline
- Follow-up create/update/list and date validation
- User and role administration
- Audit logging
- Dashboard KPIs
- Pipeline, conversion and user-activity reports
- OpenAPI/Swagger documentation
- Responsive frontend

## Important assignment note

The provided assignment PDF explicitly specifies ASP.NET Core Identity and Entity Framework Core. This project is intentionally implemented in Python/FastAPI/SQLite instead, so it is a functional equivalent and should not be described as using ASP.NET Core Identity or EF Core.
