FROM alpine:3.4

MAINTAINER Roger Steneteg <roger@steneteg.org>

# Install container dependencies
RUN apk add --no-cache git supervisor python3 redis

COPY start_supervisord.sh /opt/
COPY supervisor_redis.ini /etc/supervisor.d/
COPY supervisor_thatpassword.ini /etc/supervisor.d/

# Install that-password dependencies
RUN git clone https://github.com/rogst/that-password.git /opt/thatpassword && \
    pip3 install -r /opt/thatpassword/requirements.txt

# Install uwsgi as the python web server
RUN apk add --no-cache g++ linux-headers python3-dev && \
    pip3 install uwsgi

# HTTP interface
EXPOSE 80

# Stats interface
EXPOSE 8080

CMD ["/bin/sh", "/opt/start_supervisord.sh"]