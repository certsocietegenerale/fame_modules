FROM python:3.9

RUN pip install stringsifter

COPY script.py /app/script.py

VOLUME ["/data"]

WORKDIR /data

ENTRYPOINT ["python", "/app/script.py"]
