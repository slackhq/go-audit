## kibana ##

There isn't really any file based configuration required to make `kibana` work.

Download and install the version compatible with your elasticsearch version:
- [4.x](https://www.elastic.co/downloads/past-releases/kibana-4-6-2) (if running elasticsearch 2.x)

On Ubuntu:

```
wget https://download.elastic.co/kibana/kibana/kibana-4.6.2-amd64.deb
sudo dpkg -i kibana-4.6.2-amd64.deb 
```

Start or restart `kibana`

- 14.04 - `sudo /etc/init.d/kibana start`
- 16.04 - `sudo systemctl start kibana.service`

You will need to have installed and setup `rsyslog`, `go-audit`, and `streamstash` before you can complete the
install

When you visit `kibana` for the first time in a web browser, usually via `http://someip:5601`, it will have you
do a one time setup.

You will want to set:

- `Index name or pattern` = `streamstash-*`
- `Time-field name` = `@timestamp`

You can now hit `create` and then `Discover`, you should start to see data!

Logs will be sent to syslog, usually end up at `/var/log/syslog`
