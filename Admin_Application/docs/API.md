# AMTEL Admin API

All API endpoints require an authenticated admin session. Login through `/login` before calling them from a browser or internal tool.

## Endpoints

- `GET /api/overview?days=30` returns overview metrics, traffic trends, top pages, countries, referrers, reports, and recent visits.
- `GET /api/realtime` returns live visitors, live page views, active sessions, current locations, and recent page views.
- `GET /api/clicks?days=30` returns button/link click summaries and raw click events.
- `GET /api/conversions?days=30` returns conversion summaries and raw conversion events.
- `GET /api/engagement?days=30` returns time-spent and scroll-depth summaries plus raw engagement events.
- `GET /api/visitor-ips?days=365` returns grouped visitor IP addresses with visits, sessions, first seen, last seen, location, device, browser, and ISP.
- `GET /api/analytics/pages?days=30` returns page analytics.
- `GET /api/analytics/careers?days=30` returns careers page analytics.
- `GET /api/analytics/jobs?days=30` returns job application analytics.
- `GET /api/analytics/devices?days=30` returns device analytics.
- `GET /api/analytics/browsers?days=30` returns browser analytics.
- `GET /api/analytics/countries?days=30` returns country analytics.
- `GET /api/analytics/sources?days=30` returns traffic source analytics.
- `GET /api/reports?days=90` returns daily, weekly, and monthly reports.

## Security

- API routes use the same `login_required` session protection as the dashboard.
- Mutating form actions use CSRF tokens.
- SQL queries use parameter binding through `mysql-connector-python`.
- Admin request, login, error, and suspicious activity logs are stored in MySQL.
