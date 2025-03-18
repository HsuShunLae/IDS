import tkinter as tk
from tkinter import ttk 
from Alert import Alert
import threading
from threading import Thread, Event

class AlertBoard():
    def __init__(self, root, max_alerts):
        # Thread.__init__(self)
        self.max_alerts = max_alerts
        self.alerts = []
        self.root = root
        self.canvas = None
        self.inner_frame = None
        self.alert_labels = []
        self.stop_event = threading.Event()

    def add_alert(self, alert):
        if len(self.alerts) >= self.max_alerts:
            print("Alert board is full. Some alerts may have been discarded.")
            self.alerts.pop(0)  # Remove the oldest alert
        self.alerts.append(alert)

    def display_alerts(self):
        # self.root = tk.Tk()
        # self.root.title("Alerts")
        
        self.alert_frame = ttk.Frame(self.root)
        self.alert_frame.pack(fill=tk.BOTH, expand=True)

        # Create a scrollable canvas
        self.canvas = tk.Canvas(self.alert_frame)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(self.alert_frame, orient=tk.VERTICAL, command=self.canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.configure(yscrollcommand=scrollbar.set)

        # Create a frame to contain the alerts
        self.inner_frame = ttk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.inner_frame, anchor=tk.NW)

        for alert in self.alerts:
            alert_label = ttk.Label(self.inner_frame, text=alert.message)
            alert_label.pack(anchor=tk.W, padx=10, pady=5)
            self.alert_labels.append(alert_label)

        # Update the canvas scroll region
        self.inner_frame.update_idletasks()
        self.canvas.config(scrollregion=self.canvas.bbox("all"))

    def update_alerts(self):
        if self.root is None:
            print("errorr")
            return
        
        new_alerts = self.alerts[len(self.alert_labels):]
        if new_alerts:
            for alert in new_alerts:
                alert_label = ttk.Label(self.inner_frame, text=alert.message, foreground=alert.color)
                alert_label.pack(anchor=tk.W, padx=10, pady=5)
                self.alert_labels.append(alert_label)

            # Update the canvas scroll region
            self.inner_frame.update_idletasks()
            self.canvas.config(scrollregion=self.canvas.bbox("all"))
    
    def start_gui(self):
        self.display_alerts()
        self.update_alerts()
        self.root.protocol("WM_DELETE_WINDOW", self.close_window)
        self.root.mainloop()
        
    
    def close_window(self):
        self.stop_event.set()
        self.root.after(0, self.root.quit)  # Exit the main loop after the current event is processed
        self.root.destroy()