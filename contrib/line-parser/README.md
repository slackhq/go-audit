## `line-parser`

This program uses [`streamstash`](https://github.com/nbrownus/streamstash) to decode `go-audit` output

It takes log lines from stdin and outputs the decoded json on stdout

### Install

Make sure you have [nodejs](https://nodejs.org/en/download/) installed, the latest LTS version is advised.

Then either run `npm install` within this directory or `npm install -g https://github.com/nbrownus/streamstash#2.0`
to install `streamstash` globally

### Usage

If you already have `go-audit` logging to a local file then your best bet is to run the following command

```
tail -f /path/to/file.log | ./line-parser
```
