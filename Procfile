web: gunicorn fund_app:app
worker: celery -A fund_app.celery worker --loglevel=info --time-limit=120