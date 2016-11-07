## elastalert ##

### Things to install

- `python`
- `python-dev`
- `pip`
- `gcc`

On Ubuntu:

```
sudo apt install python python-dev python-pip gcc
```

[elastalert docs](http://elastalert.readthedocs.io/en/latest/running_elastalert.html#downloading-and-configuring) has a
good guide to getting setup.

A TLDR version:

```
sudo pip install --upgrade setuptools pip
cd /opt
sudo git clone https://github.com/Yelp/elastalert.git
cd elastalert
sudo python setup.py install
sudo pip install -r requirements.txt
# just answer the defaults for this one
elastalert-create-index --host localhost --port 9200 --no-ssl --no-auth
```

Place the files:

- [`elastalert.yaml`](./elastalert.yaml)
- [`run_uptime.yaml`](./run_uptime.yaml)
- [`systemd.service`](./systemd.service) - if running `systemd`
- [`upstart.conf`](./upstart.conf) - if running `upstart`

Logs will be sent to syslog, usually end up at `/var/log/syslog`

Once all that is done you can test the `run_uptime.yaml` rule with (you may want to run `uptime` first)

```
uptime
elastalert-test-rule --config /etc/elastalert.yaml /opt/elastalert_rules/run_uptime.yaml
```

You should see a big json blob of you running `uptime`!

Start or restart `elastalert`

- 14.04 - `sudo start elastalert`
- 16.04 - `sudo systemctl start elastalert.service`

Logs will be sent to syslog, usually end up at `/var/log/syslog`

Alerts will be sent to `/tmp/alerts`
