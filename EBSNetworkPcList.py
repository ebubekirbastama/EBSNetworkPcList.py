import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import ARP, Ether, srp

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EBS Ağ Tarayıcı")
        self.root.geometry("600x400")

        # UI Elemanları
        self.create_widgets()

    def create_widgets(self):
        # Tarama Butonu
        self.scan_button = ttk.Button(self.root, text="Ağ Taramasını Başlat", command=self.scan_network)
        self.scan_button.pack(pady=10)

        # Sonuçlar Alanı
        self.results_area = scrolledtext.ScrolledText(self.root, width=70, height=20)
        self.results_area.pack(pady=10)

    def scan_network(self):
        self.results_area.delete('1.0', tk.END)  # Önceki sonuçları temizle
        ip_range = "192.168.1.0/24"  # Burayı ağınıza göre değiştirin

        # ARP Paketlerini Gönderme
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]

        # Sonuçları Gösterme
        self.results_area.insert(tk.END, f"{'IP Adresi':<20} {'MAC Adresi':<20}\n")
        self.results_area.insert(tk.END, '-'*40 + '\n')
        for sent, received in result:
            self.results_area.insert(tk.END, f"{received.psrc:<20} {received.hwsrc:<20}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
