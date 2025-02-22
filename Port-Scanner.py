import socket
import threading
import tkinter as tk
from tkinter import messagebox, filedialog
import csv
import platform
import argparse


def scan_port(ip, port, results):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                results.append((port, 'Open'))
                try:
                    s.send(b'\r\n')
                    banner = s.recv(1024).decode().strip()
                    results.append((port, f'Banner: {banner}'))
                except Exception:
                    results.append((port, 'Banner: Not available'))
            else:
                results.append((port, 'Closed'))
    except Exception as e:
        results.append((port, f'Error: {str(e)}'))


def get_os_info():
    try:
        os_info = platform.uname()
        return f"System: {os_info.system}, Node: {os_info.node}, Release: {os_info.release}, Version: {os_info.version}, Machine: {os_info.machine}, Processor: {os_info.processor}"
    except Exception as e:
        return f"Error retrieving OS information: {str(e)}"

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

def terminal_scan(ip, start_port, end_port, save_file, show_os):
    print(f"Scanning {ip} from port {start_port} to {end_port}...")

    if show_os:
        os_info = get_os_info()
        print(f"\nLocal System Information:\n{os_info}\n")

    results = start_scan(ip, start_port, end_port)
    for port, status in results:
        if isinstance(status, tuple):
            print(f"Port {status[0]}: {status[1]}")
        else:
            print(f"Port {port}: {status}")

    if save_file:
        with open(save_file, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Status'])
            for port, status in results:
                if status.lower() == 'open':
                    writer.writerow([port, status])
        print(f"\nResults saved to {save_file}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Port Scanner')
    parser.add_argument('-i', type=str, help='Target IP address')
    parser.add_argument('-s', nargs='*', help='Specify port range or use "-p-" to scan all ports')
    parser.add_argument('-f', type=str, help='File to save results')
    parser.add_argument('-o', '--os-info', action="store_true",help='Get Os information')
    parser.add_argument('--gui', action="store_true", help='Load GUI')
    args = parser.parse_args() 

    if args.p == ['-']:
        start_port, end_port = 1, 65535
    elif args.p and len(args.p) == 2:
        start_port, end_port = int(args.p[0]), int(args.p[1])
    else:
        parser.error("Invalid port range specified")

    if not args.i and args.gui:
        terminal_scan(args.i, start_port, end_port, args.f, args.o, args.gui)    
    else:


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

        def on_scan():
            ip = ip_entry.get()
            start_port = int(start_port_entry.get())
            end_port = int(end_port_entry.get())
            if not ip or not start_port or not end_port:
                messagebox.showerror('Error', 'Please fill in all fields')
                return
            os_info = get_os_info()
            results_text.insert(tk.END, f"\nLocal System Information:\n{os_info}\n\n")
            results_text.delete(1.0, tk.END)
            results_text.insert(tk.END, f"Scanning {ip} from port {start_port} to {end_port}...\n")
            results = start_scan(ip, start_port, end_port)
            for port, status in results:
                if isinstance(status, tuple):
                    results_text.insert(tk.END, f"Port {status[0]}: {status[1]}\n")
                else:
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
                            writer.writerow([port.split()[1], status])
            messagebox.showinfo('Success', 'Results saved successfully')

        tk.Button(app, text='Start Scan', command=on_scan).pack(pady=10)
        tk.Button(app, text='Save Results', command=save_results).pack(pady=10)

        results_text = tk.Text(app, height=20, width=60)
        results_text.pack(pady=10)

        app.mainloop()