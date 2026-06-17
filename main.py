from scapy.all import sniff
import pyodbc

conn = pyodbc.connect(
    "DRIVER={SQL Server};"
    "SERVER=NITHIN-KUMAR\\SQLEXPRESS;"
    "DATABASE=packet_analyzer;"
    "Trusted_Connection=yes;"
)

cursor = conn.cursor()

stop_capture = False

def get_protocol_name(protocol_number):

    if protocol_number == 1:
        return "ICMP"

    elif protocol_number == 2:
        return "IGMP"

    elif protocol_number == 6:
        return "TCP"

    elif protocol_number == 17:
        return "UDP"
   

commit_counter = 0
def packet_callback(packet):
    
    global commit_counter
    

    if packet.haslayer("IP"):

        protocol_number = packet["IP"].proto

        protocol_name = get_protocol_name(protocol_number)

        packet_size = len(packet)

        try:
            cursor.execute("""
            INSERT INTO packets
            (source_ip, destination_ip, protocol, packet_size)
            VALUES (?, ?, ?, ?)
            """,
            (
                packet["IP"].src,
                packet["IP"].dst,
                protocol_name,
                packet_size
            ))
            
            commit_counter += 1

            if commit_counter % 100 == 0:
                conn.commit()

        except Exception as e:
            conn.rollback()
            print(f"Error inserting packet: {e}")

def should_stop(packet):
    return stop_capture

def stop_capture_function():
    global stop_capture
    stop_capture = True

def start_capture():

    global stop_capture
    global commit_counter

    stop_capture = False
    commit_counter = 0  

    print("Packet capture started...")

    sniff(
    prn=packet_callback,
    stop_filter=should_stop
    )

    conn.commit()

    print("Packet capture finished.")

