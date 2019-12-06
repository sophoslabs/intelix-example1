FROM ruby:alpine as build

COPY logstash-filter-intellix-file/ /work/logstash-filter-intellix-file/
COPY logstash-filter-intellix-web/ /work/logstash-filter-intellix-web/
RUN cd /work/logstash-filter-intellix-file/ && \
    gem build logstash-filter-intellix-file.gemspec
RUN cd /work/logstash-filter-intellix-web/ && \ 
    gem build logstash-filter-intellix-web.gemspec

FROM docker.elastic.co/logstash/logstash:7.2.0

ENV ELASTIC_HOST ############# YOUR HOST ##################
ENV ELASTIC_PORT 9200

ENV INTELLIX_CLIENT_SECRET ############ CLIENT SECRET ################
ENV INTELLIX_WEB_ENDPOINT https://de.api.labs.sophos.com/lookup/urls/v1/
ENV INTELLIX_AUTH_ENDPOINT https://de.api.labs.sophos.com
ENV INTELLIX_CLIENT_ID ############# CLIENT ID ###################
ENV INTELLIX_FILE_ENDPOINT https://de.api.labs.sophos.com/lookup/files/v1/
ENV INTELLIX_WEB_ENDPOINT https://de.api.labs.sophos.com/lookup/urls/v1/

EXPOSE 5044 5045 9600

COPY --from=build /work/logstash-filter-intellix-file/*.gem /work/
COPY --from=build /work/logstash-filter-intellix-web/*.gem /work/

RUN /usr/share/logstash/bin/logstash-plugin install --no-verify /work/*.gem

COPY file-pipeline.conf /usr/share/logstash/pipeline/file-pipeline.conf
COPY web-pipeline.conf /usr/share/logstash/pipeline/web-pipeline.conf
COPY pipelines.yml /usr/share/logstash/config/pipelines.yml
