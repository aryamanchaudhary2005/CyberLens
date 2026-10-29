FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv/cyberlens
COPY pyproject.toml ./
COPY requirements.lock ./
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./
RUN pip install --no-cache-dir -r requirements.lock .

RUN addgroup --system --gid 10001 cyberlens \
    && adduser --system --uid 10001 --ingroup cyberlens --home /srv/cyberlens cyberlens \
    && chown -R cyberlens:cyberlens /srv/cyberlens
USER cyberlens

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
