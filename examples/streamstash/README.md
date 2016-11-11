## streamstash ##

The following config will get `streamstash` handling events for the local machine. `go-audit`, `sshd`, and `sudo` logs
will be parsed.

An upstart config and systemd unit are provided as well


### Things to install

- [`nodejs`](https://nodejs.org/en/download/) - latest v4.x LTS is advised, should work on v6.x LTS

On Ubuntu:

```
sudo apt install nodejs-legacy npm git
```

On Ubuntu 14.04:

```
# 14.04 ships with a very old version of node and npm so you'll need to update npm
sudo npm install -g npm
```

To install `streamstash`

```
sudo npm install -g https://github.com/nbrownus/streamstash#2.0
```

Place the files:

- [`streamstash.js`](./streamstash.js)
- [`systemd.service`](./systemd.service) - if running `systemd`
- [`upstart.conf`](./upstart.conf) - if running `upstart`

Start or restart `streamstash`

- 14.04 - `sudo start streamstash`
- 16.04 - `sudo systemctl start streamstash.service`

Logs will be sent to syslog, usually end up at `/var/log/syslog`
