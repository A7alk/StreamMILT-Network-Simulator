import scapy.all as scapy
import json
import streamlit as st
import cv2
import easyocr
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import re

# Initialize session state if it doesn't exist
if "arp_packet" not in st.session_state:
    st.session_state["arp_packet"] = None
if "show_arp_packet" not in st.session_state:
    st.session_state["show_arp_packet"] = False

class NetworkSimulator:
    def __init__(self):
        self.network = {}
        self.attack_type = None
        self.reader = easyocr.Reader(['en'])

    def process_image(self, image_path):
        """Processes a network topology image and extracts device names and connections."""
        image = cv2.imread(image_path)
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        result = self.reader.readtext(gray)
        
        devices = [text[1] for text in result]
        self.network = {device: {"IP": device, "MAC": device} for device in devices}  # IP and MAC set as hostname
        return self.network

    def draw_network(self):
        """Allows users to draw a network interactively."""
        G = nx.Graph()
        for device in self.network.keys():
            G.add_node(device)
        
        plt.figure(figsize=(6, 6))
        nx.draw(G, with_labels=True, node_color='lightblue', edge_color='gray', node_size=3000, font_size=10)
        st.pyplot(plt)

    def extract_hosts_from_scenario(self, scenario_text):
        """Extracts host names from the scenario description using a more robust method."""
        hosts = re.findall(r'(?i)host\s*([A-Z0-9]+)', scenario_text)  # Capture host names dynamically
        unique_hosts = list(set([f"Host {h.upper()}" for h in hosts]))  # Standardize format
        
        if len(unique_hosts) < 2:
            st.warning("Not enough hosts detected. Using inferred values.")
            if len(unique_hosts) == 1:
                unique_hosts.append("Host B" if unique_hosts[0] != "Host B" else "Host A")  # Infer second host
            else:
                unique_hosts = ["Host A", "Host B"]  # Fallback
        
        return unique_hosts

    def generate_arp_packet(self, scenario_text):
        """Generates an ARP packet dynamically based on the attack scenario."""
        hosts = self.extract_hosts_from_scenario(scenario_text)
        
        source_host = hosts[0]
        destination_host = hosts[1]
        
        arp_packet_data = [
            ["ARP Request", self.network.get(source_host, {}).get("IP", source_host),
             self.network.get(source_host, {}).get("MAC", source_host),
             self.network.get(destination_host, {}).get("IP", destination_host),
             self.network.get(destination_host, {}).get("MAC", destination_host)],
            ["Destination MAC", "Source MAC", "MAC type (IP or ARP)", "", "ARP"]
        ]
        st.session_state["arp_packet"] = pd.DataFrame(arp_packet_data, columns=["ARP operation", "Source IP", "Source MAC", "Destination IP", "Destination MAC"])
        st.session_state["show_arp_packet"] = True
    
    def execute_attack(self, scenario_text):
        """Executes the selected attack type on the extracted network and generates ARP packet immediately."""
        if not self.attack_type:
            st.error("Please select an attack type.")
            return
        
        st.success(f"Executing {self.attack_type} attack on the network...")
        self.generate_arp_packet(scenario_text)
        
        if self.attack_type == "Man-in-the-Middle (MiM)":
            self.mitm_attack(scenario_text)
        elif self.attack_type == "Denial of Service (DoS)":
            self.dos_attack()
        elif self.attack_type == "ARP Poisoning":
            self.arp_poisoning()
        else:
            st.error("Invalid attack type selected.")
    
    def mitm_attack(self, scenario_text):
        """Simulates a Man-in-the-Middle attack and displays ARP packet contents."""
        st.write(f"### Scenario: {scenario_text}")
        
        if st.session_state["show_arp_packet"] and st.session_state["arp_packet"] is not None:
            st.write("### ARP Packet Contents")
            st.table(st.session_state["arp_packet"])
        
        st.success("[+] Man-in-the-Middle attack completed.")
    
    def dos_attack(self):
        """Simulates a Denial of Service attack."""
        st.write("[+] Performing Denial of Service attack...")
        st.success("[+] Denial of Service attack completed.")
    
    def arp_poisoning(self):
        """Simulates an ARP Poisoning attack."""
        st.write("[+] Performing ARP Poisoning attack...")
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

# Scenario Input
scenario_text = st.text_area("Describe the attack scenario:", "Host E uses the Man-in-the-Middle (MiM) attack to sniff the traffic between the hosts A and D. To do that, the malicious user needs to send fake ARP request packets.")

# Execute Attack
if st.button("Execute Attack", key="execute_attack"):
    simulator.execute_attack(scenario_text)

# Ensure ARP Packet Table Stays Visible
if st.session_state["show_arp_packet"] and st.session_state["arp_packet"] is not None:
    st.write("### ARP Packet Contents")
    st.table(st.session_state["arp_packet"])
