FROM python:3.12

ENV BUILD_DEPS="build-essential" \
    APP_DEPS="curl libpq-dev"
RUN apt-get update \
  && apt-get install -y ${BUILD_DEPS} ${APP_DEPS} --no-install-recommends \
  && rm -rf /var/lib/apt/lists/* \
  && rm -rf /usr/share/doc && rm -rf /usr/share/man \
  && apt-get purge -y --auto-remove ${BUILD_DEPS} \
  && apt-get clean

RUN wget http://download.redis.io/redis-stable.tar.gz \
  && tar zxvf redis-stable.tar.gz \
  && cd redis-stable \
  && make \
  && make install \
  && rm -rf /app/redis-stable*

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

ADD . /app
WORKDIR /app
RUN rm -rf /app/threatnote/__pycache__

ENV FLASK_ENV="development" \
    PYTHONUNBUFFERED="true"\
    PYTHONPATH="/app/threatnote"\
    FLASK_DEBUG="true"\
    FLASK_APP="/app/threatnote/main.py"

EXPOSE 5000

CMD gunicorn -b 0.0.0.0:5000 main:app --workers 4 > /app/gunicorn-log.txt & redis-server > /app/redis-server_log.txt &rq worker enricher > /app/rq_worker_log.txt
