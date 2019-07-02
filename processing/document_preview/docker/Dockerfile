FROM python:3

RUN apt-get update && apt-get install -y poppler-utils libreoffice --no-install-recommends

COPY requirements.txt /app/requirements.txt

RUN pip install -r /app/requirements.txt

COPY script.py /app/script.py

VOLUME ["/data"]

WORKDIR /data

ENTRYPOINT ["python", "/app/script.py"]
