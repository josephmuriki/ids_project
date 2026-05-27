import joblib
import numpy as np
from scapy.all import sniff
from datetime import datetime
import sqlite3
from flow_manager import add_packet_to_flow
from flow_manager import extract_flow_features
from flow_manager import flows
from feature_extractor import extract_features

DB = "database.db"
model = joblib.load("../models/ids_model.pkl")

def process_packet(packet):

    try:

        source_ip = "Unknown"
        destination_ip = "Unknown"
        protocol = "Unknown"

        if packet.haslayer("IP"):

            source_ip = packet["IP"].src
            destination_ip = packet["IP"].dst
            protocol = packet["IP"].proto

            flow_key = add_packet_to_flow(packet)

            if flow_key is not None:

                flow_packets = flows[flow_key]

                if len(flow_packets)>= 30:

                  features = extract_flow_features(flow_packets)

                  if features is not None:
                      
                      try:
                          
                          EXPECTED_FEATURES = 78 

                          if len(features) < EXPECTED_FEATURES:
                              
                              features += [0.0] * (
                                  EXPECTED_FEATURES - len(features)
                              )

                          elif len(features) > EXPECTED_FEATURES:
                              
                              features = features[:EXPECTED_FEATURES]

                          input_data = np.array(features).reshape(1, -1)

                          prediction = model.predict(input_data)[0]

                          print("\nAI DETECTION:")
                          
                          ATTACK_LABELS = {
                              0: "Benign",
                              1: "Bot",
                              2: "DDoS",
                              3:"DoS GoldenEye",
                              4:"DoS Hulk",
                              5:"DoS Slowhttptest",
                              6:"DoS Slowloris",
                              7:"FTP-Patator",
                              8:"Heartbleed",
                              9:"Infiltration",
                              10:"PortScan",
                              11:"SSH-Patator",
                              12:"Web Attack-Brute Force",
                              13:"Web Attack Sql Injection",
                              14:"Web Attack XSS"
                          }

                          attack_name = ATTACK_LABELS.get(
                              prediction, 
                              "Unknown"
                          )

                          print("\n========== AI IDS ALERT ==========")
                          print("ATTACK TYPE:", attack_name)
                          print("PREDICTION ID:", prediction)
                          print("==================================")


                      except Exception as e:
                            print("Prediction Error:", e)

                  flows[flow_key] = []
                    
        conn = sqlite3.connect(
    DB,
    timeout=30,
    check_same_thread=False
)

        conn.execute("PRAGMA journal_mode=WAL")
        c = conn.cursor()

        c.execute("""
        INSERT INTO detections(timestamp, source, result, score, username)
        VALUES (?, ?, ?, ?, ?)
        """, (
            datetime.now(),
            source_ip,
            "Live Traffic",
            0.0,
            "system"
        ))

        conn.commit()
        conn.close()

        print(f"[+] Packet Captured: {source_ip} -> {destination_ip}")

    except Exception as e:
        print("Sniffer Error:", e)

def start_sniffing():

    print("Starting live packet capture...")

    sniff(
        prn=process_packet,
        store=False
    )

if __name__ == "__main__":
    start_sniffing()