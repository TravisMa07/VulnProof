FROM python:3.14.10-slim-bookworm@sha256:516b51cb9db2ef061e465c803e50f64361b82cefd91e525b889b967b83e83527
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /fixture
COPY requirements.lock /fixture/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock
COPY app.py runner_driver.py /fixture/
COPY downloads/example.txt /fixture/downloads/example.txt
USER 10001:10001
CMD ["python", "/fixture/runner_driver.py"]
