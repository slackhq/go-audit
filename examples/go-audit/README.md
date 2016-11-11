## go-audit ##

The files here will get `go-audit` logging to `rsyslog` and has a decent default ruleset.

An upstart config and systemd unit are provided as well

### Things to install

- `auditd` - the one that comes with your distro is fine, we just need `auditctl` for now
  - ie: `sudo apt install auditd`
- [`golang`](https://golang.org/dl/) - so you can compile `go-audit`

On Ubuntu:

```
sudo apt install auditd golang
```

To install `go-audit`

```
make
sudo cp go-audit /usr/local/bin
```

Place the files:

- [`go-audit.yaml`](./go-audit.yaml)
- [`systemd.service`](./systemd.service) - if running `systemd`
- [`upstart.conf`](./upstart.conf) - if running `upstart`

Start or restart `go-audit`

- 14.04 - `sudo start go-audit`
- 16.04 - `sudo systemctl start go-audit.service`

Logs will be in `elasticsearch`
