## rsyslog ##

The files here will configure `rsyslog` to do the normal system logging that you are probably used to
as well as prepare for ingesting `go-audit` events and outputting them to `streamstash`

### Things to install

The following packages (and their dependencies) are required for the config to work properly. You can find the 
latest versions [here](http://www.rsyslog.com/downloads/download-v8-stable/)

Version 8.20 is the minimum version for all this to work properly

- `rsyslog`
- `rsyslog-imptcp`
- `rsyslog-relp`
- [`go-rsyslog-pstats`](https://github.com/slackhq/go-rsyslog-pstats) - (optional) takes process stats from rsyslog and
    sends them to `statsite` or `statsd`, helpful for debugging issues

On Ubuntu:

```
sudo add-apt-repository ppa:adiscon/v8-stable 
sudo apt update
sudo apt install rsyslog rsyslog-imptcp rsyslog-relp
```

Place the files:

- [`rsyslog.conf`](./rsyslog.conf)
- [`01-go-audit.conf`](./01-go-audit.conf)
- [`50-default.conf`](./50-default.conf)

Start or restart `rsyslog`

- 14.04 - `sudo restart rsyslog`
- 16.04 - `sudo systemctl start rsyslog.service`

### Debugging ###

If you are having issues with your config you can get more information by running `rsyslog` directly

```
sudo rsyslogd -n
```

or with lots of debug info

```
sudo rsyslogd -nd
```

You may have to background the process to quit

