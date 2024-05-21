import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from decode import decode_snmp_message
from encode import encode_snmp_message

class SNMPApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SNMP Encoder/Decoder")

        self.tabControl = tk.ttk.Notebook(root)
        
        self.tab_encode = tk.Frame(self.tabControl)
        self.tabControl.add(self.tab_encode, text="Encode")
        
        self.tab_decode = tk.Frame(self.tabControl)
        self.tabControl.add(self.tab_decode, text="Decode")
        
        self.tabControl.pack(expand=1, fill="both")
        
        self.create_encode_tab()
        self.create_decode_tab()

    def create_encode_tab(self):
        tk.Label(self.tab_encode, text="SNMP version:").grid(row=0, column=0, sticky="e")
        self.version_entry = tk.Entry(self.tab_encode)
        self.version_entry.grid(row=0, column=1)
        
        tk.Label(self.tab_encode, text="Community:").grid(row=1, column=0, sticky="e")
        self.community_entry = tk.Entry(self.tab_encode)
        self.community_entry.grid(row=1, column=1)
        
        tk.Label(self.tab_encode, text="OID:").grid(row=2, column=0, sticky="e")
        self.oid_entry = tk.Entry(self.tab_encode)
        self.oid_entry.grid(row=2, column=1)
        
        tk.Label(self.tab_encode, text="Value:").grid(row=3, column=0, sticky="e")
        self.value_entry = tk.Entry(self.tab_encode)
        self.value_entry.grid(row=3, column=1)
        
        self.encode_button = tk.Button(self.tab_encode, text="Encode", command=self.encode_snmp)
        self.encode_button.grid(row=4, columnspan=2)
        
        self.encode_result_text = tk.Text(self.tab_encode, height=10, width=50)
        self.encode_result_text.grid(row=5, columnspan=2)

    def encode_snmp(self):
        version = int(self.version_entry.get())
        community = self.community_entry.get()
        oid = self.oid_entry.get()
        value = self.value_entry.get()
        try:
            encoded_message = encode_snmp_message(version, community, oid, value)
            self.encode_result_text.delete(1.0, tk.END)
            self.encode_result_text.insert(tk.END, encoded_message)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def create_decode_tab(self):
        tk.Label(self.tab_decode, text="Hex Encoded SNMP Message:").grid(row=0, column=0, sticky="e")
        self.hex_entry = tk.Entry(self.tab_decode, width=50)
        self.hex_entry.grid(row=0, column=1)
        
        self.decode_button = tk.Button(self.tab_decode, text="Decode", command=self.decode_snmp)
        self.decode_button.grid(row=1, columnspan=2)
        
        self.decode_result_text = tk.Text(self.tab_decode, height=10, width=50)
        self.decode_result_text.grid(row=2, columnspan=2)

    def decode_snmp(self):
        hex_str = self.hex_entry.get()
        try:
            decoded_message = decode_snmp_message(hex_str)
            self.decode_result_text.delete(1.0, tk.END)
            self.decode_result_text.insert(tk.END, decoded_message)
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = SNMPApp(root)
    root.mainloop()
