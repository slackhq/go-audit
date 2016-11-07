// /etc/streamstash.js

// Pause inputs if we have this many items in memory
streamStash.highWatermark = 30000

// Emit telemtry to statsite or statsd
telemetry('localhost', 8125)

// Listen for relp connections on localhost:5514
addInputPlugin('relp', { host: '127.0.0.1', port: 5514 })

// Send logs to elasticsearch on localhost:9200
addOutputPlugin(
    'elasticsearch',
    {
        typeField: '_type',
        timestampField: '@timestamp',
        hostname: '127.0.0.1',
        port: '9200',
        batchSize: 500,
        indexPrefix: 'streamstash'
    }
)

// If you are having issues and want to make sure events are flowing you can uncomment the following line
// and run streamstash in a terminal
//addOutputPlugin('stdout')

addFilter(function (event) {
    // Only work with events that has a syslog object, which is probably everything
    if (event.data.hasOwnProperty('syslog') === false) {
        return event.next()
    }

    // Strip the pid from the service
    if (matches = /(.*)\[([0-9]*)\]$/.exec(event.data.syslog.service)) {
        event.data.syslog.service = matches[1]
        event.data.syslog.service_pid = matches[2]
    }

    // Parse events from specific services
    switch (event.data.syslog.service) {
        case 'sshd':
            StreamStash.parsers.sshdParser(event)
            break

        case 'sudo':
            StreamStash.parsers.sudoParser(event)
            break

        case 'go-audit':
            // If you get sick of seeing the unparsed 1305 messages in kibana, uncomment this line
            // if (event.data.message.indexOf('"type":1305') >= 0) {
            //     return event.cancel()
            // }

            StreamStash.parsers.goAuditParser(event)
            break

        default:
            // Puts the json document in a field named after the parsed syslog service
            // This is an attempt to eliminate mapping conflicts in elasticsearch
            StreamStash.parsers.jsonParser(event, '_type', false, event.data.syslog.service)
    }

    // Rename syslog specific things and drop useless to us fields
    if (event.data.syslog.hasOwnProperty('facilityName')) {
        event.data.syslog['facility'] = event.data.syslog.facilityName
        delete event.data.syslog['facilityName']
    }

    if (event.data.syslog.hasOwnProperty('severityName')) {
        event.data.syslog['severity'] = event.data.syslog.severityName
        delete event.data.syslog['severityName']
    }

    if (event.data.syslog.hasOwnProperty('service')) {
        event.data['_type'] = event.data.syslog.service
    }

    delete event.data.syslog['priority']

    // Use the timestamp from the parsed data, if any
    if (event.data.syslog.hasOwnProperty('timestamp')) {
        event.data['@timestamp'] = event.data.syslog.timestamp
    }

    // Worst case use the timestamp from when the input received the event
    if (event.data.hasOwnProperty('@timestamp') === false && event.data.event_source.hasOwnProperty('timestamp')) {
        event.data['@timestamp'] = event.data.event_source.timestamp
    }

    event.next()
})
