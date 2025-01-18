import socket

# Configuration
DEST_IP = "10.0.0.2"      # Destination IP address
DEST_PORT = 5555          # Destination port
PACKET_SIZE = 188         # Size of an MPEG-TS packet in bytes
MESSAGE = "This is a test message for MPEG-TS packet simulation."  # Message to send

def send_text_as_mpegts():
    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        print(f"Sending message to {DEST_IP}:{DEST_PORT} as MPEG-TS packets...")

        # Encode the message to bytes
        message_bytes = MESSAGE.encode("utf-8")

        # Split the message into chunks that fit within MPEG-TS packets
        for i in range(0, len(message_bytes), PACKET_SIZE - 1):
            # Get the next chunk
            payload = message_bytes[i:i + (PACKET_SIZE - 1)]

            # Pad the payload with zeros if needed
            if len(payload) < (PACKET_SIZE - 1):
                payload += b'\x00' * ((PACKET_SIZE - 1) - len(payload))

            # Prepend the synchronization byte (0x47) to the payload
            packet = b'\x47' + payload

            # Send the packet via UDP
            sock.sendto(packet, (DEST_IP, DEST_PORT))

        print("Finished sending packets.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Clean up the socket
        sock.close()

if __name__ == "__main__":
    send_text_as_mpegts()
