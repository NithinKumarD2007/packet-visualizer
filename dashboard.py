import tkinter as tk
import pyodbc
from tkinter import ttk

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from main import start_capture, stop_capture_function
import threading
import google.generativeai as genai
from dotenv import load_dotenv
import os

# Database Connection
conn = pyodbc.connect(
    "DRIVER={SQL Server};"
    "SERVER=NITHIN-KUMAR\\SQLEXPRESS;"
    "DATABASE=packet_analyzer;"
    "Trusted_Connection=yes;"
)

cursor = conn.cursor()

load_dotenv()

genai.configure(
    api_key=os.getenv("GEMINI_API_KEY")
)
model = genai.GenerativeModel(
    "gemini-2.5-flash"
)

def stop_gui_capture():

    stop_capture_function()

    start_button.config(state="normal")


def run_capture():

    start_capture()

    start_button.config(state="normal")

def start_capture_thread():
    start_button.config(state="disabled")

    capture_thread = threading.Thread(
        target=run_capture
    )

    capture_thread.daemon = True

    capture_thread.start()

def ask_ai_thread():

    question = question_entry.get()

    response_box.delete(
        "1.0",
        tk.END
    )

    response_box.insert(
        tk.END,
        "Thinking..."
    )

    def worker():

        cursor.execute(
            "SELECT COUNT(*) FROM packets WHERE protocol='TCP'"
        )
        tcp = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM packets WHERE protocol='UDP'"
        )
        udp = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM packets WHERE protocol='IGMP'"
        )
        igmp = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM packets"
        )
        total = cursor.fetchone()[0]

        cursor.execute("""
        SELECT TOP 1 source_ip, COUNT(*) as cnt
        FROM packets
        GROUP BY source_ip
        ORDER BY cnt DESC
        """)

        top_ip = cursor.fetchone()

        cursor.execute("""
        SELECT protocol, COUNT(*) as cnt
        FROM packets
        GROUP BY protocol
        ORDER BY cnt DESC
        """)

        rows = cursor.fetchall()
        prompt = f"""
        You are a professional Network Analyst.

        Current Network Statistics:

        Total Packets = {total}
        TCP Packets = {tcp}
        UDP Packets = {udp}
        IGMP Packets = {igmp}

        Most Active Source IP = {top_ip[0]}
        Packet Count From IP = {top_ip[1]}

        User Question:
        {question}

        Answer only using the database statistics above.
        """
        
        response = model.generate_content(prompt)
        
        response_box.delete(
            "1.0",
            tk.END
        )

        response_box.insert(
            tk.END,
            response.text
        )
    threading.Thread(
        target=worker,
        daemon=True
    ).start()

# Main Window
root = tk.Tk()

top_frame = tk.Frame(root)
top_frame.pack(fill="x")


bottom_frame = tk.Frame(root)
bottom_frame.pack(fill="both", expand=True)


root.title("Packet Analyzer Dashboard")
root.geometry("1400x800")


main_frame = tk.Frame(root)
main_frame.pack(fill="both", expand=True)
main_frame.grid_columnconfigure(0, weight=1)
main_frame.grid_columnconfigure(1, weight=3)
main_frame.grid_columnconfigure(2, weight=2)

left_frame = tk.Frame(main_frame)
left_frame.grid(row=0,column=0,padx=10)

center_frame = tk.Frame(main_frame)
center_frame.grid(row=0,column=1,padx=10)

right_frame = tk.Frame(main_frame)
right_frame.grid(row=0,column=2,padx=10)


start_button = tk.Button(
     left_frame,
    text="Start Capture",
    command=start_capture_thread
)

start_button.pack(pady=5)

stop_button = tk.Button(
     left_frame,
    text="Stop Capture",
    command=stop_gui_capture
)

stop_button.pack(pady=5)

# Title
title = tk.Label(
    center_frame,
    text="Packet Analyzer Dashboard",
    font=("Arial", 18)
)

title.pack(pady=10)

# Statistics Labels
total_title = tk.Label(
    left_frame,
    text="TOTAL PACKETS",
    font=("Arial",12,"bold")
)
total_title.pack(pady=(10,0))

total_label = tk.Label(
    left_frame,
    font=("Arial",28,"bold"),
    fg="cyan"
)
total_label.pack()

tcp_label = tk.Label(left_frame, font=("Arial", 12))
tcp_label.pack()

udp_label = tk.Label(left_frame, font=("Arial", 12))
udp_label.pack()

igmp_label = tk.Label(left_frame, font=("Arial", 12))
igmp_label.pack()

threat_title = tk.Label(
    left_frame,
    text="THREAT LEVEL",
    font=("Arial",12,"bold")
)

threat_title.pack(pady=(15,0))

threat_label = tk.Label(
    left_frame,
    font=("Arial",20,"bold")
)

threat_label.pack()

# Matplotlib Figure
fig = Figure(figsize=(3, 3))

ax = fig.add_subplot(111)

canvas = FigureCanvasTkAgg(fig, master=left_frame)

canvas.get_tk_widget().pack(pady=20)

recent_label = tk.Label(
    center_frame,
    text="Recent Packets",
    font=("Arial", 14, "bold")
)
recent_label.pack(pady=5)

tree = ttk.Treeview(
    center_frame,
    columns=("ID", "Source", "Destination", "Protocol"),
    show="headings",
    height=5
)

tree.heading("ID", text="ID")
tree.heading("Source", text="Source IP")
tree.heading("Destination", text="Destination IP")
tree.heading("Protocol", text="Protocol")

tree.column("ID", width=80)
tree.column("Source", width=180)
tree.column("Destination", width=180)
tree.column("Protocol", width=100)

tree.pack(
    fill="both",
    expand=True,
    padx=10,
    pady=10
)

ai_label = tk.Label(
    right_frame,
    text="AI Network Assistant",
    font=("Arial", 14, "bold")
)

ai_label.pack(pady=10)

question_entry = tk.Entry(
    right_frame,
    width=80
)

question_entry.pack(pady=5)

ask_button = tk.Button(
    right_frame,
    text="Ask AI",
    command=ask_ai_thread
)

ask_button.pack(pady=5)

response_box = tk.Text(
    right_frame,
    height=12,
    width=45,
    bg="#111111",
    fg="#00FF66",
    font=("Consolas",10)
)

response_box.pack(pady=5)

previous_count = 0

pps_label = tk.Label(
    left_frame,
    font=("Arial",12,"bold"),
    fg="lime"
)

pps_label.pack(pady=10)

def update_stats():
    
    # Total Packets
    cursor.execute(
        "SELECT COUNT(*) FROM packets"
    )

    total = cursor.fetchone()[0]

    global previous_count

    pps = total - previous_count

    previous_count = total

    # TCP Count
    cursor.execute(
        "SELECT COUNT(*) FROM packets WHERE protocol='TCP'"
    )

    tcp = cursor.fetchone()[0]

    # UDP Count
    cursor.execute(
        "SELECT COUNT(*) FROM packets WHERE protocol='UDP'"
    )

    udp = cursor.fetchone()[0]

    # IGMP Count
    cursor.execute(
        "SELECT COUNT(*) FROM packets WHERE protocol='IGMP'"
    )

    igmp = cursor.fetchone()[0]

    if udp > 1000:
        threat = "HIGH"

    elif udp > 300:
        threat = "MEDIUM"

    else:
        threat = "LOW"

    # Update Labels
    total_label.config(
    text=f"{total}"
    )

    pps_label.config(
    text=f"PPS : {pps}"
    )

    tcp_label.config(
        text=f"TCP Packets : {tcp}"
    )

    udp_label.config(
        text=f"UDP Packets : {udp}"
    )

    igmp_label.config(
        text=f"IGMP Packets : {igmp}"
    )

    if threat == "LOW":
        threat_label.config(
        text=threat,
        fg="green"
    )

    elif threat == "MEDIUM":
        threat_label.config(
            text=threat,
            fg="orange"
        )

    else:
        threat_label.config(
            text=threat,
            fg="red"
    )
    cursor.execute("""
    SELECT TOP 10
    id,
    source_ip,
    destination_ip,
    protocol
    FROM packets
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    

    for item in tree.get_children():
        tree.delete(item)

    for row in rows:
        tree.insert(
            "",
            tk.END,
            values=(
                row[0],
                row[1],
                row[2],
                row[3]
            )
        )

    # Update Pie Chart
    ax.clear()

    labels = ["TCP", "UDP", "IGMP"]

    values = [tcp, udp, igmp]

    ax.set_title("Protocol Distribution")


    if tcp + udp + igmp > 0:

        ax.pie(
            values,
            labels=labels,
            autopct="%1.1f%%"
        )


    else:
        ax.text(
            0.5,
            0.5,
            "No Packet Data",
            ha="center",
            va="center"
        )
    canvas.draw()
    # Refresh every 5 seconds
    root.after(5000, update_stats)

   

# Start Updating
update_stats()

# Run GUI
root.mainloop()