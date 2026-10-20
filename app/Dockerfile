FROM python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4
WORKDIR /app
COPY app /app/app
COPY web /app/web
COPY openapi.json /app/openapi.json
COPY README.md /app/README.md
RUN mkdir /data && chown 1000:1000 /data
USER 1000:1000
ENV DATA_DIR=/data/private PORT=18805 CF_ALLOW_WRITES=false
EXPOSE 18805
CMD ["python", "/app/app/server.py"]
