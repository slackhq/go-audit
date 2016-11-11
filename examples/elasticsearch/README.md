## elasticsearch ##

Very bare bones approach to getting elasticsearch running

## Things to install ##

- `java`
- [`elasticsearch`](https://www.elastic.co/downloads/past-releases/elasticsearch-2-4-1) - Avoid using 5.x until [elastalert supports it](https://github.com/Yelp/elastalert/issues/510)
- [`kopf`](https://github.com/lmenezes/elasticsearch-kopf) - makes ops a lot easier

On Ubuntu 16.04:

```
sudo apt install openjdk-8-jre-headless
```

On Ubuntu 14.04:

```
sudo apt install openjdk-7-jre-headless
```

On Ubuntu:

```
wget https://download.elastic.co/elasticsearch/release/org/elasticsearch/distribution/deb/elasticsearch/2.4.1/elasticsearch-2.4.1.deb
sudo dpkg -i elasticsearch-2.4.1.deb
```

Place the files

- [`elasticsearch.yml`](./elasticsearch.yml)

Start or restart `elasticsearch`

- 14.04 - `sudo /etc/init.d/elasticsearch start`
- 16.04 - `sudo systemctl start elasticsearch.service`

Once the service is running apply the [`mapping.json`](./mapping.json) template to prepare for `streamstash` logs

```
curl -d @mapping.json http://localhost:9200/_template/streamstash
```

Logs are usually at `/var/log/elasticsearch/elasticsearch.log`
