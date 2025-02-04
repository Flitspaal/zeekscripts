# Define logs for different types of events
export 
{
    redef enum Log::ID += 
    {
        MPEGTS_LOG,  # Log for MPEG-TS packets
        CONNECTION_LOG  # Log for connections
    };

    # All global variables:
    # Global valid check for MPEG-TS packets
    global valid_check: string = "false";
    # Global counter for invalid logs
    global invalid_count: count = 0;
    # Global queue for the last 100 logs.
    global last_100_logs: table[string] of transport_proto = table();
    # global temp
    global temp: count = 0;

    # MPEG-TS packet log structure
    type MpegtsInfo: record 
    {
        packet_time: time &log;
        uid: string &log;
        source_ip: addr &log;
        source_port: port &log;
        receive_ip: addr &log;
        receive_port: port &log;
        payload_size: int &log;
        valid: string &log;
    };

    # Connection log structure
    type ConnectionInfo: record 
    {
        connection_time: time &log;
        uid: string &log;
        source_ip: addr &log;
        source_port: port &log;
        dest_ip: addr &log;
        dest_port: port &log;
        protocol: transport_proto &log;  # transport Protocol type (TCP/UDP)
        status: string &log;
    };
}

# Create separate log files
event zeek_init() 
{
    # MPEG-TS log stream
    Log::create_stream(MPEGTS_LOG, [$columns=MpegtsInfo, $path="MPEGTS_LOG"]);

    # Connection log stream
    Log::create_stream(CONNECTION_LOG, [$columns=ConnectionInfo, $path="CONNECTION_LOG"]);
}

# Event for each new connection
event new_connection(c: connection)
{
    print fmt("New connection detected: %s:%d -> %s:%d (Proto: %s)", 
              c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, c$id$resp_p);  # Use c$id$proto here

    # Log the connection details using the correct protocol from the connection record
    local log_entry: ConnectionInfo = [
        $connection_time = network_time(),
        $uid=c$uid,
        $source_ip=c$id$orig_h,
        $source_port=c$id$orig_p,
        $dest_ip=c$id$resp_h,
        $dest_port=c$id$resp_p,
        $protocol=get_port_transport_proto(c$id$orig_p),  # Use c$proto here
        $status="New Connection"
    ];
    Log::write(CONNECTION_LOG, log_entry);
    # add new connection to the table
    if (|last_100_logs| >= 100)
    {
        for(a in last_100_logs)
        {
	    delete last_100_logs[a];
	    print fmt("%d", |last_100_logs|);
	    return;
        }
        return;
    }
    
    last_100_logs[c$uid] = get_port_transport_proto(c$id$orig_p);
    print last_100_logs[c$uid];
}


# Event for inspecting UDP payloads to detect MPEG-TS packets and verify DNS packets
event udp_contents(c: connection, is_orig: bool, payload: string) 
{
    # payload starts with a PRI (priority) header that provides info about the serverity and facilitate of the log message
    if (c$id$resp_p == 514/udp) {
        if(payload[0] == "<" && payload[1] in "0123456789") {
            # print fmt("syslog packet");
        }
        else { print fmt("fake syslog packet"); }
    }
    # Detect MPEG-TS packets on port 5555/udp  // || c$id$orig_p == 5555/udp
    if (c$id$resp_p == 5555/udp) {
        if (|payload| >= 188 && payload[0] == "\x47") {
            valid_check = "true";
        } else {
            valid_check = "false";
        }
        # Log the MPEG-TS packet
        local log_entry: MpegtsInfo = [
            $packet_time=network_time(),
            $uid=c$uid,
            $source_ip=c$id$orig_h,
            $source_port=c$id$orig_p,
            $receive_ip=c$id$resp_h,
            $receive_port=c$id$resp_p,
            $payload_size=|payload|,
            $valid=valid_check
        ];
        Log::write(MPEGTS_LOG, log_entry);
    }
}

# Event triggered when a connection is terminated
event connection_state_remove(c: connection) 
{
    # Print termination in terminal
    print fmt("Terminated connection: %s:%d -> %s:%d (Port: %s)", 
              c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, c$id$resp_p);  # Use c$proto here

    # Log the connection termination
    local log_entry: ConnectionInfo = [
        $connection_time=network_time(),
        $uid=c$uid,
        $source_ip=c$id$orig_h,
        $source_port=c$id$orig_p,
        $dest_ip=c$id$resp_h,
        $dest_port=c$id$resp_p,
        $protocol=get_port_transport_proto(c$id$orig_p),  # Use c$proto here
        $status="Connection Terminated"
    ];
    Log::write(CONNECTION_LOG, log_entry);
}

event zeek_done()
{
    print fmt("-------------------------------------------");
    print fmt("amount: %d", |last_100_logs|);
    print fmt("-------------------------------------------");
    for([a], uid in last_100_logs)
    {
        print fmt("transport protocol: %s, uid: %s",last_100_logs[a] , a);
    }
    print fmt("-------------------------------------------");
}
