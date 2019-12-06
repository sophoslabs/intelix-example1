# SLAP the beat
SLAP the beat is an experimental project, enhancing elastic beats with Sophos Labs Analytics Platforms (SLAP).
We provide two filter plugins for Logstash: for Packetbeat and Auditbeat to lookup domain/sha256 reputations.
We provide an Auditbeat module to upload files to static/dynamic analysis to SLAP. The module polls the result and sends the result directly to elasticsearch.

This project is experimental. Please **be careful** where you start the beats for the lookup endpoints as they harvest a lot of data, and the **lookups are not free**.

##  Prerequisites:
Installed and running Elasticsearch/Kibana 7.2
Working knowledge of elastic framework including beats.
Working knowledge of docker.
You need to have Sophos Intelix API credentials*

## Installing:
## ELK - Reputation lookup
At the time of creation elastic 7.2.0 was the latest version. Hence we provide the steps with version ELK verion 7.2.0. Supposedly works with both oss and basic.
#### Logstash
cd elk/
Fill out the 'Dockerfile' accordingly with:
- ELASTIC_HOST Your elasticsearch instance
- INTELLIX_CLIENT_SECRET intellix client_secret
- INTELLIX_CLIENT_ID intellix client_id
docker build .
docker run -p 5044:5044 -p 5045:5045 docker_image_id
#### Packetbeat
Fires on events that contain 'server.domain'.
output.logstash:
	hosts: ["localhost:5045"]
#### Auditbeat
Fires on events that contain 'hash.sha256'.
output.logstash:
	hosts: ["localhost:5045"]
#### Kibana
Settings > Saved Objects > Import > Browse 'kibana_final.ndjson'

## Beat module - dynamic, static submisson
The beat module is basically a modification of the official file_integrity module of Auditbeat. The file_integrity can be used to detect changes to files in the specified folders, and with our modification, it uses the SLAP platform to get data about the files it encounters.

The provided code is an extension to the original Auditbeat code, so everything that is described in the official documentation applies here as well.

### Building the module
Set up the development environment and the project as described in the [Beats Developer Guide](https://www.elastic.co/guide/en/beats/devguide/7.5/index.html).

### Installing the module
The Auditbeat module can be installed directly in the operating system or can be deployed as a Docker container or a Kubernetes Pod. For more info, please refer to the [Getting started with Auditbeat](https://www.elastic.co/guide/en/beats/auditbeat/current/auditbeat-getting-started.html) and [Setting up and running Auditbeat](https://www.elastic.co/guide/en/beats/auditbeat/current/setting-up-and-running.html) guides.

### Configuring the module
Auditbeat can be configured as described in the [Configuring Auditbeat](https://www.elastic.co/guide/en/beats/auditbeat/current/configuring-howto-auditbeat.html) guide.

All the functionality Auditbeat provides can be used, but in order to use SLAP/Intelix the file_integrity module must be enabled and configured as described in the next section.

#### Configuring Intelix in the file_integrity module
The only part that is different from the original Auditbeat configuration is the configuration of the file_integrity module.

Example configuration 'auditbeat.yml' is included in the source.

Description of the options:
- **`paths`**: Specify the paths in the filesystem that should be monitored for changed files.
- **`intelix.credentials`**: These are the `clientId` and `clientSecret` that you received when you registered on api.labs.sophos.com
- **`intelix.urls`**:
  - `proxy_url`: Configure the http proxy if you need one
  - `auth_url`: The url where the authentication token can be requested
  - `intelix_url`: The url where the Intelix services are available. Configure the one nearest to you. The list of possible entries can be checked on the documentation page of the service in the Servers dropdown.
- **`intellix.query_timeout`**: How long should it wait for a query response
- **`intellix.static_analysis_reputation_threshold`**: Before sending a file for static analysis, the module requests a File Hash Lookup on it, which returns a reputation score for the file. Based on the reputation score and this threshold it can decide whether the file should be sent for analysis.
  See the [https://api.labs.sophos.com/doc/lookup/files.html](documentation) for the meaning of the values.
  Set it to 100 to send all files for analysis.
- **`intellix.dynamic_analysis_score_threshold`**: The same as above but for dynamic analysis.
- **`intellix.static_analysis`**:
  - `min_size`: Files below this size are not sent for analysis
  - `max_size`: Files above this size are not sent for analysis.
    NOTE: the api has its own maximum filesize limit above which it rejects the submissions.
  - `report_poll_interval`: How often poll for the report after a file has been submitted.
    The Static and Dynamic analysis APIs work in two ways:
    - If the submitted file is already known, they return the result immediately
    - If the submitted file has not yet been analysed, then after submission, we need to poll the /reports/{job_id} endpoint periodically for the results
  - `analysis_timeout`: Time out polling for the results after this many seconds.
- **`intellix.dynamic_analysis`**: The same as above for dynamic analysis.


## License
This project is licensed under Apache License, Version 2.0. See the LICENSE file for full license text.

## Acknowledgements
https://www.elastic.co/products/beats
https://github.com/coolacid/logstash-filter-virustotal
https://api.labs.sophos.com/doc/index.html
