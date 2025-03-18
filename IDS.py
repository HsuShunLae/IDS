from scapy.all import *
import argparse
import logging
from datetime import datetime
import sys
from SIDS.RuleRead import read
from AIDS.Anomaly import *
import keyboard
from Alert_Board import *
from tkinter import *
RED = '\033[91m'
BLUE = '\033[34m'
GREEN = '\033[32m'
ENDC = '\033[0m'

def main(filename, pcap):
    # Read the rule file and start listening.

    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    logging.basicConfig(filename= "logs\\Simple-NIDS " + str(now) + '.log',level=logging.INFO)

    print ("Simple-NIDS started.")
    # Read the rule file
    print ("Reading rule file...")
    global ruleList
    global pcap_file
    global alertboard
    root = Tk()
    root.title("Alerts")
    alertboard = AlertBoard(root, 1000)
    pcap_file = pcap
    ruleList, errorCount = read(filename, alertboard)
    print ("Finished reading rule file.")

    if (errorCount == 0):
        print ("All (" + str(len(ruleList)) + ") rules have been correctly read.")
    else:
        print (str(len(ruleList)) + " rules have been correctly read.")
        print (str(errorCount) + " rules have errors and could not be read.")

    sniffer = detect(ruleList, pcap_file, alertboard)

    def on_esc(event):
        sniffer.stop()
        print("ESC pressed. Stopping Simple-NIDS.")
        
        
    # # Set up the 'q' key event handler
    keyboard.on_press_key("esc", on_esc)
    process_thread = threading.Thread(target=sniffer.run)
    process_thread.daemon = True
    process_thread.start()
    
    # Start the tkinter GUI in the main thread
    alertboard.start_gui()


    # Wait for the packet processing thread to finish
    process_thread.join()
    
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Hybrid NIDS')
    parser.add_argument('-f', '--filename', help='Path to the rule file', required=True)
    parser.add_argument('-c', '--pcap', help='Path to the offline pcap file', required=False)
    args = parser.parse_args()
    
    ruleList = list()
    if args.pcap:
        main(args.filename, args.pcap)
    else:
        pcap=None
        main(args.filename, args.pcap)
    


