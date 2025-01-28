import socket
import threading
import tkinter as tk
from tkinter import messagebox, filedialog
import csv


def scan_port(ip, port, results):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                results.append((port, 'Open'))
            else:
                results.append((port, 'Closed'))
    except Exception as e:
        results.append((port, f'Error: {str(e)}'))

def start_scan(ip, start_port, end_port):
    results = []
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(ip, port, results))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    return results

def on_scan():
    ip = ip_entry.get()
    start_port = int(start_port_entry.get())
    end_port = int(end_port_entry.get())
    if not ip or not start_port or not end_port:
        messagebox.showerror('Error', 'Please fill in all fields')
        return
    results_text.delete(1.0, tk.END)
    results_text.insert(tk.END, f"Scanning {ip} from port {start_port} to {end_port}...\n")
    results = start_scan(ip, start_port, end_port)
    for port, status in results:
        results_text.insert(tk.END, f"Port {port}: {status}\n")

def save_results():
    results = results_text.get(1.0, tk.END).strip().split('\n')
    if not results or "Port" not in results[0]:
        messagebox.showerror('Error', 'No results to save')
        return
    
    file_path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files', '*.csv')])
    if file_path:
        with open(file_path, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Status'])
            for result in results[1:]:
                if ":" in results:
                    port, status = result.split(': ', 1)
                    if status.lower() == 'open':
                        writer.writerow([port.split()[1], status])
        messagebox.showinfo('Success', 'Results saved successfully')


app = tk.Tk()
app.title('Port Scanner')
app.geometry('500x500')


tk.Label(app, text="Target IP:").pack(pady=5)
ip_entry = tk.Entry(app)
ip_entry.pack(pady=5)

tk.Label(app, text="Start Port:").pack(pady=5) 
start_port_entry = tk.Entry(app)
start_port_entry.pack(pady=5)

tk.Label(app, text="End Port:").pack(pady=5)
end_port_entry = tk.Entry(app)
end_port_entry.pack(pady=5)

tk.Button(app, text='Start Scan', command=on_scan).pack(pady=10)
tk.Button(app, text='Save Results', command=save_results).pack(pady=10)

results_text = tk.Text(app, height=20, width=60)
results_text.pack(pady=10)

app.mainloop()