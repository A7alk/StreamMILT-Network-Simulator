import scapy.all as scapy
import json
import streamlit as st
from PIL import Image
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import re
import openai

# Initialize session state if it doesn't exist
if "arp_packet" not in st.session_state:
    st.session_state["arp_packet"] = None
if "show_arp_packet" not in st.session_state:
    st.session_state["show_arp_packet"] = False
if "network_analyzed" not in st.session_state:
    st.session_state["network_analyzed"] = False
if "analysis_result" not in st.session_state:
    st.session_state["analysis_result"] = ""

# Load API key securely from Streamlit secrets
OPENAI_API_KEY = st.secrets["OPENAI_API_KEY"]
client = openai.OpenAI(api_key=OPENAI_API_KEY)

class NetworkSimulator:
    def __init__(self):
        self.network = {}

    def process_image(self, image_path):
        """Processes a network topology image and extracts device names and connections."""
        image = Image.open(image_path).convert('L')  # Convert image to grayscale
        
        # Simple placeholder OCR using numpy (since Tesseract is unavailable)
        detected_text = ["Host A", "Host B", "Host C", "Host D", "Host E"]  # Example extracted data
        
        self.network = {device: {"IP": device, "MAC": device} for device in detected_text}  # IP and MAC set as hostname
        st.session_state["network_analyzed"] = True
        return self.network

    def analyze_network_with_gpt(self, scenario_text):
        """Uses GPT-4 to analyze the uploaded network and generate the correct number of ARP packets based on the attack scenario."""
        if not st.session_state["network_analyzed"]:
            st.error("Please upload and analyze a network diagram first.")
            return
        
        prompt = f"""
        You are an AI network security expert specializing in network attacks and ARP spoofing detection.
        Based on the following attack scenario:
        
        {scenario_text}
        
        - Identify the type of attack being described.
        - Determine how many ARP packets are needed to execute the attack successfully.
        - Generate structured ARP packets formatted exactly as follows for each required packet:
        
        ```
        ARP operation   |   Source IP   |   Source MAC   |   Destination IP   |   Destination MAC
        -------------------------------------------------------------------------------------------
        ARP Request     |   [Source_IP] |   [Source_MAC] |   [Dest_IP]       |   [Dest_MAC]
        -------------------------------------------------------------------------------------------
        Destination MAC |   Source MAC |   MAC type (IP or ARP)
        -------------------------------------------------------------------------------------------
        [Dest_MAC]      |   [Source_MAC] |   ARP
        ```
        
        Ensure each generated ARP packet is specific to the attack and does not contain placeholder values. The number of packets should correspond directly to what is required to perform the attack effectively.
        
        Do not include additional explanations—only return the structured ARP packets.
        """
        
        try:
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "system", "content": "You are a network security expert. Always generate the correct number of ARP packet details in the specified format based on the attack scenario."},
                          {"role": "user", "content": prompt}]
            )
            analysis = response.choices[0].message.content
        except Exception as e:
            analysis = f"Error in AI analysis: {str(e)}"
        
        st.session_state["analysis_result"] = analysis
    
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
if st.button("Analyze with GPT", key="analyze_gpt"):
    simulator.analyze_network_with_gpt(scenario_text)

# Display AI Analysis Result
if st.session_state["analysis_result"]:
    st.write("### AI Analysis Result")
    st.write(st.session_state["analysis_result"])
