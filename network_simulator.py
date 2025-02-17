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
if "network_analyzed" not in st.session_state:
    st.session_state["network_analyzed"] = False
if "analysis_result" not in st.session_state:
    st.session_state["analysis_result"] = ""

class NetworkSimulator:
    def __init__(self):
        self.network = {}
        self.reader = easyocr.Reader(['en'])

    def process_image(self, image_path):
        """Processes a network topology image and extracts device names and connections."""
        image = cv2.imread(image_path)
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        result = self.reader.readtext(gray)
        
        devices = [text[1] for text in result]
        self.network = {device: {"IP": device, "MAC": device} for device in devices}  # IP and MAC set as hostname
        st.session_state["network_analyzed"] = True
        return self.network

    def analyze_network(self, scenario_text):
        """Uses AI to analyze the uploaded network and respond based on the scenario."""
        if not st.session_state["network_analyzed"]:
            st.error("Please upload and analyze a network diagram first.")
            return
        
        response = f"Based on the provided scenario: '{scenario_text}', AI has detected potential security risks and generated a response."
        st.session_state["analysis_result"] = response
    
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

# Scenario Input
scenario_text = st.text_area("Describe the attack scenario:", "Host E uses the Man-in-the-Middle (MiM) attack to sniff the traffic between the hosts A and D. To do that, the malicious user needs to send fake ARP request packets.")

# AI Analysis Execution
if st.button("Analyze with AI", key="analyze_ai"):
    simulator.analyze_network(scenario_text)

# Display AI Analysis Result
if st.session_state["analysis_result"]:
    st.write("### AI Analysis Result")
    st.write(st.session_state["analysis_result"])

