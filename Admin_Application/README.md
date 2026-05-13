# AMTEL Admin Analytics

Professional Flask admin application for monitoring the AMTEL website through a MySQL analytics database.

## Features

- Sidebar-based overview dashboard with total visitors, active users, daily/monthly visitors, returning visitors, bounce rate, conversions, top pages, trends, and geographic traffic.
- Dedicated analytics pages for pages, careers, job applications, devices, browsers, countries, and traffic sources.
- Real-time monitoring for live visitors, page views, active sessions, and current locations.
- Button and link click tracking with visitor IP, page, target URL, device, browser, and CSV export.
- Conversion tracking for contact form submissions, newsletter signups, and job apply clicks.
- Time-spent and scroll-depth tracking for engagement analytics.
- Visitor IP address reporting with first seen, last seen, visits, sessions, location, device, browser, and ISP.
- Visitor statistics, CSV export, daily/weekly/monthly reports, and entry/exit analytics.
- Logs for admin activity, requests, errors, and suspicious activity.
- Security controls: admin login, password hashing support, session auth, CSRF protection, login rate limiting, secure cookie options, protected APIs, environment-based secrets, and parameterized SQL.

## Setup

1. Create a MySQL database user or update `.env` with your existing MySQL credentials.
2. Copy `.env.example` to `.env` and fill in production values.
3. Install dependencies:

```powershell
pip install -r requirements.txt
```

4. Initialize the database:

```powershell
flask --app app db upgrade
```

5. Run the public website from `amtelkom.com` so visits are recorded:

```powershell
python app.py
```

6. Run this admin application:

```powershell
python app.py
```

7. Open `http://127.0.0.1:5001` and login with the credentials from `.env`.

## Database

- Database name: `amtelkom_analytics`
- Runtime schema initializer: `analytics_repository.init_database()`
- SQL schema: `sql/schema.sql`
- Migration starter: `sql/001_admin_monitoring_migration.sql`
- CLI commands: `flask --app app db upgrade`, `flask --app app db init`, and `flask --app app db status`

## Documentation

- API documentation: `docs/API.md`
- Deployment guide: `docs/DEPLOYMENT.md`

## Production Notes

- Replace `ADMIN_SECRET_KEY`, `FLASK_SECRET_KEY`, `ANALYTICS_IP_HASH_SALT`, and any default password before deployment.
- Use `ADMIN_PASSWORD_HASH` instead of `ADMIN_PASSWORD`.
- Set `ADMIN_COOKIE_SECURE=true` when the admin app is served over HTTPS.
- Keep `.env` out of source control.
- If the site is behind Nginx, Cloudflare, or another proxy, keep forwarding `X-Forwarded-For` so visitor IPs are recorded correctly.
