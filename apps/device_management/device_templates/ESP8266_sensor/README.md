# ESP8266 C3DS Sensor Node - Setup Guide

**C3DS** - Civilian Distributed Drone Detection System
**Hardware:** ESP8266 (NodeMCU / Wemos D1 Mini) + HC-SR04 Ultrasonic Sensor
**Security:** ECDSA P-256 cryptographic signatures

---

## What This Device Does

This IoT sensor detects objects within 25cm using an ultrasonic sensor and securely reports them to a central server. It's designed for the C3DS distributed sensor network project.

**Features:**
- Automatic heartbeat messages every 20 seconds (when idle)
- Alert messages when objects detected (every 10 seconds while detecting)
- Cryptographically signed messages (ECDSA P-256)
- WiFi connectivity with automatic reconnection
- Visual LED status indicators

---

## What You Need

### Hardware
1. **ESP8266 board** (NodeMCU or Wemos D1 Mini)
2. **HC-SR04 ultrasonic sensor**
3. **4 jumper wires** (female-to-female recommended)
4. **USB cable** (Micro-USB for most ESP8266 boards)
5. **Computer** (Windows, Mac, or Linux)

### Software
1. **Arduino IDE** (version 1.8.13 or newer)
   - Download from: https://www.arduino.cc/en/software
2. **ESP8266 board support** (we'll install this in Step 1)
3. **USB drivers** (usually auto-installed, see troubleshooting if needed)

---

## Step-by-Step Setup

### Step 1: Install Arduino IDE and ESP8266 Support

1. **Download and install Arduino IDE**
   - Go to https://www.arduino.cc/en/software
   - Download the installer for your operating system
   - Run the installer and follow the prompts

2. **Add ESP8266 board support**
   - Open Arduino IDE
   - Go to **File → Preferences**
   - In "Additional Board Manager URLs", paste:
     ```
     http://arduino.esp8266.com/stable/package_esp8266com_index.json
     ```
   - Click **OK**

3. **Install ESP8266 boards**
   - Go to **Tools → Board → Boards Manager**
   - Search for "esp8266"
   - Click **Install** on "esp8266 by ESP8266 Community"
   - Wait for installation to complete (may take a few minutes)

### Step 2: Install Required Libraries

The code needs two libraries. Install them from the Arduino Library Manager:

1. **ArduinoJson**
   - Go to **Sketch → Include Library → Manage Libraries**
   - Search for "ArduinoJson"
   - Install **ArduinoJson by Benoit Blanchon** (version 6.x)

2. **micro-ecc**
   - In the Library Manager, search for "micro-ecc"
   - Install **micro-ecc by Kenneth MacKay**

### Step 3: Connect the Hardware

**HC-SR04 to ESP8266 Wiring:**

| HC-SR04 Pin | ESP8266 Pin | Wire Color (suggestion) |
|-------------|-------------|-------------------------|
| VCC         | 5V (VU)     | Red                     |
| GND         | GND         | Black                   |
| TRIG        | D1 (GPIO5)  | Yellow                  |
| ECHO        | D2 (GPIO4)  | Green                   |

**Important Notes:**
- Double-check connections before powering on
- The HC-SR04 needs 5V power (use the Vin pin, not 3V3)
- Keep wires as short as possible to reduce noise

**LED Indicators (built-in):**
- **Status LED (D6):** Blinks rapidly during detection
- **Built-in LED (D4):** Shows WiFi status

### Step 4: Verify Configuration

This code bundle has been pre-configured with your device's credentials.

**You don't need to edit config.h** - everything is ready to upload!

**Optional:** If you want to see your configuration, open the `config.h` tab in Arduino IDE. All values have been automatically generated for your device.

### Step 5: Connect and Select Your Board

1. **Connect ESP8266 to computer**
   - Plug in the USB cable
   - Wait for drivers to install (first time only)
   - You should see a new COM port appear

2. **Select the correct board**
   - Go to **Tools → Board**
   - Select your board:
     - **NodeMCU 1.0 (ESP-12E Module)** for NodeMCU
     - **LOLIN(WEMOS) D1 R2 & mini** for Wemos D1 Mini

3. **Select the correct port**
   - Go to **Tools → Port**
   - Select the COM port that appeared when you plugged in the board
   - **Windows:** Usually COM3, COM4, or higher
   - **Mac:** Usually /dev/cu.usbserial-XXXX
   - **Linux:** Usually /dev/ttyUSB0 or /dev/ttyUSB1

4. **Configure upload settings** (go to **Tools** menu)
   - **Upload Speed:** 115200
   - **CPU Frequency:** 80 MHz
   - **Flash Size:** 4MB (FS:2MB OTA:~1019KB)
   - **Erase Flash:** "Only Sketch" (for updates), "All Flash Contents" (first time)

### Step 6: Open the Project

1. **Open the .ino file**
   - In Arduino IDE, go to **File → Open**
   - Navigate to the downloaded folder
   - Open `ESP8266_P256.ino` (or the main .ino file)
   - All related files (.cpp, .h, config.h) will open automatically in tabs

### Step 7: Upload the Code

1. **Verify the code compiles**
   - Click the **checkmark icon** (✓) or press **Ctrl+R** (Cmd+R on Mac)
   - Wait for compilation (may take 30-60 seconds)
   - Check the bottom output window for "Done compiling"

2. **Upload to ESP8266**
   - Click the **right arrow icon** (→) or press **Ctrl+U** (Cmd+U on Mac)
   - Wait for "Connecting..." message
   - You should see dots appearing: `........_____.....`
   - Upload takes about 30-60 seconds
   - When done, you'll see: "Hard resetting via RTS pin..."

3. **Monitor the serial output**
   - Go to **Tools → Serial Monitor**
   - Set baud rate to **115200** (bottom-right dropdown)
   - You should see the device boot sequence:
     ```
     ╔════════════════════════════════════════════════╗
     ║         C3DS - IoT Sensor Node v1.0            ║
     ║  Civilian Distributed Drone Detection System   ║
     ╚════════════════════════════════════════════════╝
     ```

---

## Understanding the Output

Once uploaded, the Serial Monitor shows the device status:

### Boot Sequence (one-time)
1. **Hardware Initialization** - Configures pins and LEDs
2. **Network Connection** - Connects to WiFi (shows dots while connecting)
3. **Time Synchronization** - Syncs with NTP server for timestamps
4. **Cryptographic Initialization** - Loads ECDSA key
5. **Messaging Subsystem** - Verifies crypto and time are ready

### Normal Operation
You'll see messages like:
```
[HW] Distance: 156.2 cm | Detection: IDLE | Valid readings: 0
[MAIN] Heartbeat interval reached
[MSG] SUCCESS - Message accepted by server
```

### When Object Detected (< 25cm)
```
[HW] ═══════════════════════════════════
[HW] OBJECT DETECTED!
[HW] Distance: 18.3 cm
[MAIN] Alert triggered by object detection!
[MSG] SUCCESS - Message accepted by server
```

---

## Troubleshooting

### Upload Issues

**"Failed to connect to ESP8266"**
- Unplug and replug the USB cable
- Try pressing the "FLASH" button while uploading (some boards require this)
- Check if the correct COM port is selected
- Try a different USB cable (some cables are power-only)

**"Port is not available" or "Access denied"**
- Close Serial Monitor before uploading
- Check if another program is using the port
- Restart Arduino IDE
- On Linux: Add your user to the `dialout` group

**"esptool.py not found"**
- Reinstall ESP8266 board support (Tools → Board → Boards Manager)
- Check Arduino installation is not in a protected folder

### Connection Issues

**WiFi won't connect**
- Verify WiFi credentials in config.h are correct
- Make sure you're connecting to a 2.4GHz network (ESP8266 doesn't support 5GHz)
- Move closer to the WiFi router
- Check if your network has MAC filtering enabled

**NTP synchronization fails**
- Check internet connection
- Try changing `NTP_SERVER` in config.h to "time.google.com"
- Check firewall isn't blocking UDP port 123

**Server connection fails**
- Verify the server is accessible from your network
- Check server is running and accepting connections
- If using HTTP (not HTTPS), ensure firewall allows connection
- Check the Serial Monitor for specific error codes

### Sensor Issues

**Always shows "Invalid sensor reading"**
- Check HC-SR04 wiring (TRIG to D1, ECHO to D2)
- Make sure HC-SR04 is powered from 5V (Vin pin)
- Try moving sensor away from metal objects
- Check for loose connections

**False detections**
- Sensor may be too close to a wall or object
- Adjust `DETECTION_THRESHOLD_CM` in config.h (default: 25cm)
- Increase `CONSECUTIVE_READINGS_REQUIRED` (default: 2)

### Certificate/Authentication Issues

**"AUTHENTICATION FAILED (401/403)"**
- Certificate may have expired - regenerate from C3DS portal
- Check system clock is synchronized (NTP must succeed first)
- Verify device is activated by admin in C3DS portal

**"Failed to sign message"**
- This shouldn't happen with auto-generated config
- If it does, regenerate and re-download the code bundle
- Contact system administrator

---

## Testing Your Setup

### Quick Test Checklist

1. **Power On**
   - Plug in USB cable
   - Both LEDs should blink briefly
   - Built-in LED should stay on after WiFi connects

2. **Check Serial Monitor**
   - Open Serial Monitor (115200 baud)
   - Should see "DEVICE READY" message
   - Should see "Heartbeat sent successfully" every 20 seconds

3. **Test Sensor**
   - Wave your hand 15-20cm in front of HC-SR04
   - Status LED should blink rapidly
   - Serial Monitor shows "OBJECT DETECTED!"
   - Should see "Alert message sent successfully"

4. **Verify Server Reception**
   - Check C3DS admin panel
   - Should see heartbeat messages arriving
   - Should see alert messages when you trigger detection

---

## Advanced Configuration

### Adjusting Detection Sensitivity

Edit `config.h` (lines 57-63):

```cpp
// Make more sensitive (detect at greater distance)
#define DETECTION_THRESHOLD_CM 30.0  // Changed from 25.0

// Reduce false positives (require more consecutive readings)
#define CONSECUTIVE_READINGS_REQUIRED 3  // Changed from 2
```

### Changing Message Intervals

Edit `config.h` (lines 46-48):

```cpp
// Send heartbeats less frequently
static const unsigned long HEARTBEAT_INTERVAL = 60000;  // 60 seconds (was 20)

// Send alerts more frequently during detection
static const unsigned long ALERT_INTERVAL = 5000;  // 5 seconds (was 10)
```

### Updating Firmware

1. Make your changes in Arduino IDE
2. Click **Upload** (→)
3. Device will restart automatically with new firmware
4. **Note:** Set "Erase Flash" to "Only Sketch" to preserve WiFi credentials

**Warning:** Never share your `config.h` file - it contains your private cryptographic key!

---

## Pin Reference

**ESP8266 Pin Mapping:**

| Arduino Pin | GPIO | NodeMCU Label | Function in This Project |
|-------------|------|---------------|--------------------------|
| D1          | 5    | D1            | HC-SR04 TRIG             |
| D2          | 4    | D2            | HC-SR04 ECHO             |
| D4          | 2    | D4            | Built-in WiFi LED        |
| D6          | 12   | D6            | Status LED               |
| VU          | -    | VU/5V         | HC-SR04 VCC (5V)         |
| GND         | -    | GND           | HC-SR04 GND              |

---

## Security Notes

**Important:**
- The private key in `config.h` is **sensitive** - never share it publicly
- Each device has a unique certificate and private key
- This configuration is pre-generated specifically for your device
- Never commit `config.h` to version control (e.g., GitHub)
- If compromised, regenerate certificate from C3DS portal

**Certificate Validity:**
- Your device certificate is valid for a limited time (check C3DS portal)
- When expired, you'll need to regenerate and re-download the code bundle
- The device will show authentication errors when certificate expires

---

## Support

**Common Questions:**
- Make sure you're using Arduino IDE version 1.8.13 or newer
- ESP8266 board support should be version 3.0.0 or newer
- ArduinoJson must be version 6.x (not 7.x)
- If compilation errors, check all libraries are installed

**Additional Resources:**
- ESP8266 Arduino Core Docs: https://arduino-esp8266.readthedocs.io/
- ArduinoJson Documentation: https://arduinojson.org/
- HC-SR04 Datasheet: Search "HC-SR04 datasheet" online

---

## Project Information

**Academic Project:** BSc Computer Science Final Year Project
**Focus:** Secure IoT Device Management for Distributed Sensor Networks
**Security:** ECDSA P-256 signatures, X.509 certificates
**Protocol:** HTTP REST API with certificate-based authentication

**Version:** 1.1
**Last Updated:** 2026-01-27

---

## License & Credits

This is an academic project developed as part of BSc Computer Science coursework:
Secure IoT Device Management in a Safety-critical Smart Environment

**Libraries Used:**
- ESP8266 Arduino Core (LGPL 2.1)
- ArduinoJson by Benoit Blanchon (MIT)
- micro-ecc by Kenneth MacKay (BSD-2-Clause)

---

**Ready to upload?** Your device is pre-configured and ready to go!

Just connect your ESP8266, select the board and port, and click Upload!