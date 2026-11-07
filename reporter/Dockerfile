FROM python:3.12-slim
# pango/harfbuzz are what WeasyPrint uses to lay out text for the PDF
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir jinja2==3.1.6 weasyprint==66.0
WORKDIR /app
COPY report.py template.html ./
COPY fonts ./fonts
ENV PYTHONUNBUFFERED=1
CMD ["python", "report.py", "serve"]
