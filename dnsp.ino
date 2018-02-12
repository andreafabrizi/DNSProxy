/*
 Copyright: (c) SAEKI Yoshiyasu, Massimiliano Fantuzzi HB3YOE
 Analog inputs attached to pins A0 through A5 (optional)
*/

#include <SPI.h>
#include <Ethernet.h>
#include <Udp.h>

#define STACK_SIZE (1024 * 1024)    /* Stack size for cloned child */
#define DELAY        0
#define MAXCONN             1
#define UDP_DATAGRAM_SIZE   256
#define DNSREWRITE          256
#define HTTP_RESPONSE_SIZE  256
#define URL_SIZE            256
#define VERSION             "1.1"
#define DNS_MODE_ANSWER     1
#define DNS_MODE_ERROR      2
#define DEFAULT_LOCAL_PORT  53
#define DEFAULT_WEB_PORT    80
#define NUMT              4
#define NUM_THREADS         4
#define NUM_HANDLER_THREADS 1

#define MISO       50   //num 10 on nano
#define MOSI       51   //num 11 on nano
#define SCLK       52   //num 12 on nano
#define CLK        52

//#define SS_PIN      53  //from MFRC522
//#define SPI_SS      53  // from RFM12B
//#define RST_LCD     53
//#define CS           8   //6
#define SS          53
//#define SPI_SS_PIN  53  //from Robot_Control/SdCard.h

#define SD_CS        6
#define SPI_SS      53
#define SPI_CS       8

//#define ETHERNET_SHIELD_SPI_CS  8;

#define PACKET_MAX_SIZE 512

byte macOne[] = {  0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xEC };
byte macTwo[] = {  0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };

//byte ip[] = {192, 168, 254, 100};
byte resIp[] = {192, 168, 3, 241};

unsigned int listenPort = 53;
byte remoteIp[4];
unsigned int remotePort;

char requestBuffer[PACKET_MAX_SIZE];
char responseBuffer[PACKET_MAX_SIZE];

IPAddress ipOne(192,168,1,241);
IPAddress ipTwo(192,168,3,241);
IPAddress dnsOne(192,168,1,1);
IPAddress dnsTwo(192,168,3,1);
IPAddress gatewayOne(192, 168,1,1);
IPAddress gatewayTwo(192, 168,3,1);
IPAddress subnet(255,255,255,0);

//IPAddress ip(192, 168, 1, 241);
EthernetUDP Udp;
EthernetUDP UdpOne;
EthernetUDP UdpTwo;

EthernetServer serverOne(80);
EthernetServer serverTwo(80);
//EthernetServer server(80);

boolean currentLineIsBlank = true;
char c;

const uint8_t SD_CHIP_SELECT = 5;
const int8_t DISABLE_CHIP_SELECT = 6;

//#define ETH_CS_PIN  8   //from enc28j60_tutorial-master/_18_SDWebserver/_18_SDWebserver.ino
//#define ethCSpin    8

void setup()
{
  Serial.begin(9600);
  /*
  while (!Serial) {
    ;
  }
  */
  
  /*
  if (DISABLE_CHIP_SELECT < 0) {
    //cout << F(
    //       "\nAssuming the SD is the only SPI device.\n"
    //       "Edit DISABLE_CHIP_SELECT to disable another device.\n");
  } else {
    //cout << F("\nDisabling SPI device on pin ");
    //cout << int(DISABLE_CHIP_SELECT) << endl;
    pinMode(DISABLE_CHIP_SELECT, OUTPUT);
    digitalWrite(DISABLE_CHIP_SELECT, HIGH);
  }
  */
 
  pinMode(8,OUTPUT);
  digitalWrite(8,HIGH);

  pinMode(7,OUTPUT);
  digitalWrite(7,HIGH);

  startOne();
  delay(200);
  startTwo();
  delay(200);
  
  Serial.println(F("Ready"));
}

void loop() {
  //checkServerOne();
  //checkServerTwo();
  
/*
  // listen for incoming clients
  EthernetClient client = server.available();
  if (client) {
    Serial.println("new client");
    // an http request ends with a blank line
    boolean currentLineIsBlank = true;
    while (client.connected()) {
      if (client.available()) {
        char c = client.read();
        Serial.write(c);
        // if you've gotten to the end of the line (received a newline
        // character) and the line is blank, the http request has ended,
        // so you can send a reply
        if (c == '\n' && currentLineIsBlank) {
          // send a standard http response header
          client.println("HTTP/1.1 200 OK");
          client.println("Content-Type: text/html");
          client.println("Connection: close");  // the connection will be closed after completion of the response
          client.println("Refresh: 5");  // refresh the page automatically every 5 sec
          client.println();
          client.println("<!DOCTYPE HTML>");
          client.println("<html>");
          // output the value of each analog input pin
          for (int analogChannel = 0; analogChannel < 6; analogChannel++) {
            int sensorReading = analogRead(analogChannel);
            client.print("analog input ");
            client.print(analogChannel);
            client.print(" is ");
            client.print(sensorReading);
            client.println("<br />");
          }
          client.println("</html>");
          break;
        }
        if (c == '\n') {
          // you're starting a new line
          currentLineIsBlank = true;
        } else if (c != '\r') {
          // you've gotten a character on the current line
          currentLineIsBlank = false;
        }
      }
    }
    // give the web browser time to receive the data
    delay(1);
    // close the connection:
    client.stop();
    Serial.println("client disconnected");
  }
*/

  int requestSize = UdpTwo.parsePacket(); //int requestSize = Udp.available();
  
  if(requestSize) {
    Serial.print("Received packet of size ");
    Serial.println(requestSize);
    Serial.print("From ");
    
    IPAddress remote = UdpTwo.remoteIP();

    for (int i = 0; i < 4; i++) {
      Serial.print(remote[i], DEC);
      if (i < 3) {
        Serial.print(".");
      }
    }
    Serial.print(", port ");
    Serial.println(UdpTwo.remotePort());

    //Udp.readPacket(requestBuffer, PACKET_MAX_SIZE, remoteIp, remotePort);
    UdpTwo.read(requestBuffer, PACKET_MAX_SIZE);

    int type = (requestBuffer[2] >> 3) & 15;
    if(type == 0) {            // nomal request
      int ini = 12;
      int lon = requestBuffer[ini];
      char domain[64];
      int i = 0;
      while(lon != 0) {
        for(int j = 0; j < lon; j++) {
          domain[i++] = requestBuffer[ini + j + 1];
        }
        domain[i++] = '.';
        ini += lon + 1;
        lon = requestBuffer[ini];
      }
      domain[i] = '\0';
      Serial.println(domain);
      /*
      - ANSWER
        //response[0] = 0x81;
        response[0] = 0x85;
        response[1] = 0x80;
        response+=2;
        // Questions 1
        response[0] = 0x00;
        response[1] = 0x01;
        response+=2;
        //Answers 1
        response[0] = 0x00;
        response[1] = 0x01;
        response+=2;

      - ERROR
        response[0] = 0x81;
        response[1] = 0x82;
        response+=2;
        // Questions 1
        response[0] = 0x00;
        response[1] = 0x01;
        response+=2;
        // Answers 0
        response[0] = 0x00;
        response[1] = 0x00;
        response+=2;
        
      */
      
      if(domain[0] != '\0') {  // request exists
        int resIndex = 0;
        for(int k = 0; k < 2; k++) {            // identification
          responseBuffer[resIndex++] = requestBuffer[k];
        }
        responseBuffer[resIndex++] = '\x85';    // response   //81
                                                // recursion desired
        responseBuffer[resIndex++] = '\x80';    // recursive
                                                // no error
        //for(int k = 4; k < 6; k++) {            // question
          //responseBuffer[resIndex++] = requestBuffer[k];
          responseBuffer[resIndex++] = '\x00';
          responseBuffer[resIndex++] = '\x01';
        //}
        //for(int k = 4; k < 6; k++) {            // answer
          //responseBuffer[resIndex++] = requestBuffer[k];
          responseBuffer[resIndex++] = '\x00';
          responseBuffer[resIndex++] = '\x01';
        //}
        for(int k = 0; k < 4; k++) {            // authority, addition
          responseBuffer[resIndex++] = '\x00';
        }

        //for(int k = 12; k < requestSize - 8; k++) {  // question
        for(int k = 0; k < requestSize; k++) {  // question
          responseBuffer[resIndex++] = requestBuffer[k];
        }

        /*
          // Type
          response[0] = (uint8_t)(dns_req->qtype >> 8);
          response[1] = (uint8_t)dns_req->qtype;
          response+=2;
          
          // Class
          response[0] = (uint8_t)(dns_req->qclass >> 8);
          response[1] = (uint8_t)dns_req->qclass;
          response+=2;
        */
        
        responseBuffer[resIndex++] = '\xc0';    // pointer to answer
        responseBuffer[resIndex++] = '\x0c';

        /* TYPES */
/*        
  if (dns_req->qtype == 0x0f) { //MX
          response[0] = 0x00;
          response[1] = 0x0f;
          response+=2;
  } else if (dns_req->qtype == 0xFF) { //ALL
          response[0] = 0x00;
          response[1] = 0xFF;
          response+=2;
  } else if (dns_req->qtype == 0x01) { //A
    *response++ = 0x00;
    *response++ = 0x01;
  } else if (dns_req->qtype == 0x05) { //CNAME
          response[0] = 0x00;
          response[1] = 0x05;
          response+=2;
  } else if (dns_req->qtype == 0x0c) { //PTR
          response[0] = 0x00;
          response[1] = 0x0c;
          response+=2;
  } else if (dns_req->qtype == 0x02) { //NS
          response[0] = 0x00;
          response[1] = 0x02;
          response+=2;
  } else { return; }
*/
  
        responseBuffer[resIndex++] = '\x00';    // type A
        responseBuffer[resIndex++] = '\x01';
        
        responseBuffer[resIndex++] = '\x00';    // class
        responseBuffer[resIndex++] = '\x01';
        
        responseBuffer[resIndex++] = '\x00';    // ttl (orig 0x3c, now 4 hours)
        responseBuffer[resIndex++] = '\x00';
        
        responseBuffer[resIndex++] = '\x38';
        responseBuffer[resIndex++] = '\x40';    // ttl end
        
        responseBuffer[resIndex++] = '\x00';    // ip length for A record
        responseBuffer[resIndex++] = '\x04';
        responseBuffer[resIndex++] = resIp[0];  // ip
        responseBuffer[resIndex++] = resIp[1];
        responseBuffer[resIndex++] = resIp[2];
        responseBuffer[resIndex++] = resIp[3];
        
        //responseBuffer[resIndex++] = '\x00';    // end
     
        Serial.println("Contents:");
        Serial.println(requestBuffer);

        //Udp.sendPacket((uint8_t *)responseBuffer, (uint16_t)(resIndex - 1),remoteIp, remotePort);
        UdpTwo.beginPacket(UdpTwo.remoteIP(), UdpTwo.remotePort());
        UdpTwo.write((uint8_t *)responseBuffer, (uint16_t)(resIndex - 1));
        UdpTwo.endPacket();
      }
    }
  }
  //delay(10);
}

void startOne()
{
  Ethernet.select(8);
  Ethernet.begin(macOne, ipOne, dnsOne, gatewayOne, subnet);
  //Udp.begin(listenPort);
  UdpOne.begin(listenPort);
  serverOne.begin();
}

void startTwo()
{
  Ethernet.select(7);
  Ethernet.begin(macTwo, ipTwo, dnsTwo, gatewayTwo, subnet);
  //Udp.begin(listenPort);
  UdpTwo.begin(listenPort);
  serverTwo.begin();
}

void checkServerOne() {
  // select ethernet one
  Ethernet.select(8);
  checkClient(1);
}

void checkServerTwo() {
  // select ethernet two
  Ethernet.select(7);
  checkClient(2);
}

void checkClient(int board) {
  EthernetClient client;
  
  if (board > 0 && board < 2) {
    EthernetClient client = serverOne.available();
  } else if (board > 1 && board < 3) {
    EthernetClient client = serverTwo.available();
  } else { return; }
  
  currentLineIsBlank = true;
  if(client) {
    while(client.connected()) {
      if(client.available()) {
        c = client.read();
        if(c == '\n' && currentLineIsBlank)
        {
          client.println(F("HTTP/1.1 200 OK"));
          client.println(F("Content-Type: text/html"));
          client.println(F("Connection: close"));
          client.println();
          client.println(F("<!DOCTYPE HTML>"));
          client.println(F("<html><head>"));
          client.println(F("<meta http-equiv=\"refresh\" content=\"5\">"));
          client.print(F("</head><body>Hello world from ")); //ethernet one!
          client.print(board);
          client.print(F("</body>"));
          client.println(F("</html>"));
          break;
        }
        if(c == '\n')
          currentLineIsBlank = true;
        else if(c != '\r')
          currentLineIsBlank = false;
      }
    }
    client.stop();
  }
}
