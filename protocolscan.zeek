# Mpeg-ts packet inspection script.
# 02/11/2024

module Mpegtsdetect;

# create a logging structure
export {
    redef  enum Log::ID += { Mpegtsdetect::LOG };

    # is it a valid mpeg-ts packet
    option valid = "false";

    # create log for every Mpeg-ts event
    type Info: record {
        packet_time: time &log;
        source_ip: addr &log;
        source_port: port &log;
        receive_ip: addr &log;
        receive_port: port &log;
        payload_size: int &log;
        valid: string &log;
    };
}

# create log file.
event zeek_init() 
{
    Log::create_stream{LOG, [$colums=Info, $path="MpegtsDetect"]};
}

# Enhanced Zeek script to log TCP and UDP connections, detect MPEG-TS packets, and verify DNS packets
# Event for each new TCP or UDP connection
event new_connection(c: connection)
{
    # Log the connection details based on known protocol ports
    if (c$id$resp_p == 80/tcp || c$id$orig_p == 80/tcp)
        print fmt("HTTP connection: %s:%d -> %s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    else if (c$id$resp_p == 443/tcp || c$id$orig_p == 443/tcp)
        print fmt("HTTPS connection: %s:%d -> %s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    else if (c$id$resp_p == 53/udp || c$id$orig_p == 53/udp)
        print fmt("DNS connection (UDP): %s:%d -> %s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    else if (c$id$resp_p == 5555/udp || c$id$orig_p == 5555/udp) {
        print fmt("MPEG-TS connection (UDP): %s:%d -> %s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
    else {
        print fmt("New connection: %s:%d -> %s:%d (Port: %s)", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, c$id$resp_p);
    }
}

# Event for inspecting UDP payloads to detect MPEG-TS packets and verify DNS packets
event udp_contents(c: connection, is_orig: bool, payload: string)
{
    # Detect MPEG-TS packets on port 5555/udp
    if (c$id$resp_p == 5555/udp || c$id$orig_p == 5555/udp) {
        print fmt("Checking MPEG-TS payload from %s:%d -> %s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
        
        # Check if the payload length and first byte indicate an MPEG-TS packet
        if (|payload| >= 188 && payload[0] == "\x47") {
            print fmt("Real MPEG-TS packet detected: %s:%d -> %s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
            valid = "true";
        }
        else {
            print fmt("Non-MPEG-TS packet or incomplete data: %s:%d -> %s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
            valid = "false";
        }
        # create log for Mpeg-ts event
        Log::write(LOG, Info($packet_time = network_time(),
                             $source_ip = c$id$orig_h,
                             $source_port = c$id$orig_p,
                             $receive_ip = c$id$resp_h,
                             $receive_port = c$id$resp_p,
                             $payload_size = |payload|,
                             $valid = valid));
    }

    # Verify DNS packets on port 53/udp
    if (c$id$resp_p == 53/udp || c$id$orig_p == 53/udp) {
        print fmt("Checking DNS payload from %s:%d -> %s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);

        # DNS packets typically start with a 2-byte ID field, followed by flags, etc.
        if (|payload| >= 12) {
            print fmt("Valid DNS packet structure: %s:%d -> %s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
        }
        else {
            print fmt("Non-DNS packet or incomplete data: %s:%d -> %s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
        }
    }
}

# Event triggered when a connection is terminated
event connection_state_remove(c: connection)
{
    print fmt("Connection ended: %s:%d -> %s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
}
