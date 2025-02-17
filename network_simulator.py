
import scapy.all as scapy
import json
import streamlit as st
import cv2
import pytesseract
import networkx as nx
import matplotlib.pyplot as plt

class NetworkSimulator:
    def __init__(self):
        self.network = {}
        self.attack_type = None

    def process_image(self, image_path):
        """Processes a network topology image and extracts device names and connections."""
        image = cv2.imread(image_path)
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        text = pytesseract.image_to_string(gray)
        
        devices = [line.strip() for line in text.split('\n') if line.strip()]
        self.network = {device: {"IP": f"192.168.1.{i+1}", "MAC": f"AA:BB:CC:DD:EE:{i+1:02d}"} for i, device in enumerate(devices)}
        return self.network

    def draw_network(self):
        """Allows users to draw a network interactively."""
        G = nx.Graph()
        for device in self.network.keys():
            G.add_node(device)
        
        plt.figure(figsize=(6, 6))
        nx.draw(G, with_labels=True, node_color='lightblue', edge_color='gray', node_size=3000, font_size=10)
        st.pyplot(plt)

    def execute_attack(self):
        """Executes the selected attack type on the extracted network."""
        if not self.attack_type:
            st.error("Please select an attack type.")
            return
        
        st.success(f"Executing {self.attack_type} attack on the network...")
        if self.attack_type == "Man-in-the-Middle (MiM)":
            self.mitm_attack()
        elif self.attack_type == "Denial of Service (DoS)":
            self.dos_attack()
        elif self.attack_type == "ARP Poisoning":
            self.arp_poisoning()
        else:
            st.error("Invalid attack type selected.")
    
    def mitm_attack(self):
        """Simulates a Man-in-the-Middle attack."""
        st.write("[+] Performing Man-in-the-Middle attack...")
        # Add MITM logic here
        st.success("[+] Man-in-the-Middle attack completed.")
    
    def dos_attack(self):
        """Simulates a Denial of Service attack."""
        st.write("[+] Performing Denial of Service attack...")
        # Add DoS logic here
        st.success("[+] Denial of Service attack completed.")
    
    def arp_poisoning(self):
        """Simulates an ARP Poisoning attack."""
        st.write("[+] Performing ARP Poisoning attack...")
        # Add ARP poisoning logic here
        st.success("[+] ARP Poisoning attack completed.")

# Streamlit App
st.title("Stream MILT Network Simulator")

simulator = NetworkSimulator()

# Image Upload Section
uploaded_file = st.file_uploader("Upload Network Diagram (Image)", type=["png", "jpg", "jpeg"])
if uploaded_file:
    with open("temp_image.png", "wb") as f:
        f.write(uploaded_file.getbuffer())
    extracted_network = simulator.process_image("temp_image.png")
    st.json(extracted_network)
    
# Draw Network Section
if st.button("Draw Network"):
    simulator.draw_network()

# Attack Selection
attack_type = st.selectbox("Select Attack Type:", ["Man-in-the-Middle (MiM)", "Denial of Service (DoS)", "ARP Poisoning"])
simulator.attack_type = attack_type

# Execute Attack
if st.button("Execute Attack"):
    simulator.execute_attack()
