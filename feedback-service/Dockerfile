FROM python:3.12-slim
WORKDIR /app
RUN groupadd -r feedback && useradd -r -g feedback feedback
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
RUN chown -R feedback:feedback /app
USER feedback
EXPOSE 8091
CMD ["python3", "main.py"]
