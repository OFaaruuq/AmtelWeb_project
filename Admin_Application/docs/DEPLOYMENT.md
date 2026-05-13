# Deployment Guide

## Production Checklist

1. Create a dedicated MySQL user with permissions on `amtelkom_analytics`.
2. Copy `.env.example` to `.env` and set strong values for `ADMIN_SECRET_KEY`, `ADMIN_PASSWORD_HASH`, and `MYSQL_PASSWORD`.
3. Generate the admin password hash:

```powershell
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your-password'))"
```

4. Initialize the database:

```powershell
flask --app app db upgrade
```

5. Run the public website so visitor events are written by its tracking middleware.
6. Run the admin app behind a production WSGI server and reverse proxy.
7. Set `ADMIN_COOKIE_SECURE=true` when serving over HTTPS.
8. Keep `.env` out of source control.
9. Keep `ADMIN_SESSION_CHECK_INTERVAL_SECONDS` low enough to honor revoked admin sessions quickly.

## Background Aggregation

Schedule the analytics aggregation command with Task Scheduler, cron, or your process manager:

```powershell
flask --app app aggregate-analytics
```

## Runtime Notes

- The admin application listens on `ADMIN_HOST:ADMIN_PORT`.
- The public site writes visitor events into the same `MYSQL_DATABASE`.
- Real-time monitoring uses the last 15 minutes of `visitor_events`.
- Bounce rate and returning visitors are calculated from visitor hashes within the selected window.
- Job conversion is a proxy based on visits to job pages.
