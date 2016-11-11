## examples ##

The following folders contain configs for each program, together they should give you a strong
starting point for running all of this in production.

These configs are targeted for everything running on a single Ubuntu 14.04 or 16.04 host. They _should_
work for other distributions but may require some modification.

Set everything up in the following order:

1. [`elasticsearch`](./elasticsearch)
1. [`streamstash`](./streamstash)
1. [`rsyslog`](./rsyslog)
1. [`go-audit`](./go-audit)
1. [`kibana`](./kibana)
1. [`elastalert`](./elastalert)
