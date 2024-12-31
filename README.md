# Deauth-attack-using-esp8266
Research on Wi-Fi security protocols vulnerabilities 

  This document presents an implementation of a deauthentication (deauth) attack utilizing an ESP8266 NodeMCU microcontroller. The attack was executed on a personal Wi-Fi network, ensuring that no external devices were impacted. 
Nonetheless, the code can be readily modified to perform a genuine deauthentication attack.

  ## Limitations:

  - Frequency Band Restriction: The ESP8266 operates exclusively on the 2.4 GHz Wi-Fi band. Consequently, it is incompatible with most modern Wi-Fi networks, particularly home networks that predominantly utilize the 5 GHz band.
  - Security Protocol Compatibility: This type of attack is feasible only on networks employing WPA2 or earlier security protocols. The WPA3 security protocol incorporates encryption for deauthentication packets, thereby preventing such attacks.
  - Functional Constraints of ESP8266: The ESP8266 microcontroller has significant limitations when performing this specific attack, particularly concerning the wifi_send_pkt_freedom() function. This restriction affects the
microcontroller's capabilities in executing the attack effectively. (A method to circumvent this limitation will be discussed subsequently.)

  ## Additional Information

  This type of attack can be implemented on the 5 GHz bandwidth using more advanced hardware. Most inexpensive microcontrollers with Wi-Fi capabilities operate solely on the 2.4 GHz band. This limitation arises because they are 
primarily designed for Internet of Things (IoT) applications, which do not require the higher power and performance necessary for such attacks. For those interested in conducting attacks on the 5 GHz bandwidth, a Raspberry Pi is 
a viable alternative, as most models are equipped with 5 GHz-compatible Wi-Fi modules.

  The motivation behind building this project stemmed from an interest sparked during a Security Protocol course. The ESP8266 Software Development Kit (SDK) provided by the Arduino Integrated Development Environment (IDE) removes
the primary functionality required for this type of attack, specifically the wifi_send_pkt_freedom() function. The simplest solution to bypass this limitation is to install an older version of the SDK that retains this functionality.
Alternatively, one can utilize the SDK provided by Spacehuhn, for which I will include a reference link. Another method to circumvent this issue is to install the compiler supplied by Espressif, the manufacturer of the ESP8266.

  Regarding security protocols, the deauthentication attack is applicable only to networks using the WPA2 security protocol. WPA3 incorporates encryption for deauthentication packets, rendering this attack ineffective. To target WPA3 
networks, different techniques must be employed. The ESP8266 does not support attacking WPA3; however, the ESP32, which is the successor to the ESP8266, offers such support.

  Despite WPA3 being introduced in 2018, the majority of home routers have yet to adopt it. Based on local Wi-Fi network scans, none of the observed networks utilized WPA3. While I have not conducted scans on other types of networks, 
such as those in cafes or hotels, it is likely that WPA3 adoption in these environments is also limited.

  This type of attack can be categorized as a Denial of Service (DoS) attack. It does not involve stealing credentials or intercepting packets. However, I will elaborate later on how this attack can be leveraged to facilitate 
more sophisticated attacks.

# Concept Explanation

  The primary vulnerability exploited in this type of attack is the deauthentication control flow, which transmits packets that are not encrypted. Consequently, the only two resources required to disrupt access to the network
are the Media Access Control (MAC) address of the router and the MAC address of the device connected to the network.

  ## Acquisition of Necessary Information

  - BSSID Acquisition: The Basic Service Set Identifier (BSSID) can be easily obtained by scanning the local networks. Although some routers may conceal their BSSID or Service Set Identifier (SSID), this method of obscuration is
ineffective as a preventive measure.
  - Device MAC Address Acquisition: The MAC address of a device using the network can be acquired by sniffing the packets transmitted over the network. The MAC header within these packets contains both the device's MAC address and the router's
MAC address (BSSID). Since these addresses are not encrypted, they remain accessible despite attempts to hide the BSSID.

  ## Execution of the Deauthentication Attack
  
  Once the attacker has obtained the two key elements—the router's MAC address (BSSID) and the target device's MAC address—the next step is to send a deauthentication message. The structure of such a message is as follows:
  ```
  0xC0, 0x00,                          // Type, Subtype: 0xC0 for deauthentication (0xA0 for disassociation)
  0x00, 0x00,                          // Duration (handled by SDK)
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Receiver (target device)
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Source (access point)
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // BSSID (access point)
  0x00, 0x00,                          // Fragment and Sequence Number
  0x01, 0x00                           // Reason Code (1 = Unspecified Reason)

  ```

  ## Practical Considerations
  
  MAC Address Randomization: Modern smartphones implement MAC address randomization as a security measure to enhance privacy. This feature can complicate the execution of deauthentication attacks on such devices, as the randomized MAC address changes periodically, making it more challenging to maintain a persistent attack.

  #  Practical implementation

  ### Step 1. Implementing wi-fi network scanner (this step is easy to implement)
    if (!scan) {
    Serial.println("Starting Wi-Fi scan...");
    int n = WiFi.scanNetworks();
    int channel;
    if (n == 0) {
      Serial.println("No network found");
    } else {
      Serial.printf("%d networks found:\n", n);
      x = new network[n];
      for (int i = 0; i < n; i++) {
        Serial.printf("%d: %s (Channel: %d, RSSI: %d dBm)\n",
                      i + 1,
                      WiFi.SSID(i).c_str(),
                      WiFi.channel(i),
                      WiFi.RSSI(i));
        if (WiFi.SSID(i) == "bomba-bomba") {
          single_target = i;
          Serial.printf(" BSSID: ");
          printMAC(WiFi.BSSID(i));
        }
        x[i].BSSID = WiFi.BSSID(i);
        x[i].channel = WiFi.channel(i);
        x[i].RSSI = WiFi.RSSI(i);
        initBSSIDSet(x[i].set_dispozitive);
      }
    }
    scan = true;
    ---- rest of code ----
    }
   - type network is a custom structure meant to store information about the individual networks
  
  ### Step 2. Packet Sniffer

  During the development of the deauthentication attack implementation, I encountered challenges in locating the device's MAC address. Upon investigation, it became evident that the provided data structure includes a metadata header containing hardware-specific information. This header is analogous to the Radiotap header used in packet sniffing when operating in monitor mode, a concept I previously encountered while working on a firewall project.

  #### Data Structure and Metadata Header

  - The metadata header embedded within the data structure serves to convey detailed hardware information necessary for accurate packet analysis. Similar to the Radiotap header, it provides essential context that facilitates the interpretation of captured packets. Understanding this structure was crucial for diagnosing why the device MAC address was not readily identifiable in the captured data.

  - Comprehensive information regarding the format of the provided data structure is available in the ESP8266 documentation. This documentation outlines the various components of the data packets, including the metadata header, and explains how to parse and interpret the information contained within them. Familiarity with these specifications was essential for effectively utilizing the packet sniffer.

  - To implement the packet sniffing functionality, I utilized a structure definition sourced from an existing GitHub repository dedicated to packet sniffing with the ESP8266 platform. Specifically, the esp8266_pcap_serial.ino file from the repository [z4ziggy/esp8266_pcap_serial](https://github.com/z4ziggy/esp8266_pcap_serial) provided the necessary struct definitions and parsing logic. This resource proved invaluable in overcoming the initial obstacle of identifying the device MAC address by offering a proven framework for packet capture and analysis.
