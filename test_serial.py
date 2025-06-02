import serial
import time

try:
    ser = serial.Serial("COM7", 57600, timeout=1)
    print("Connected to COM7!")
    # Send a simple command (e.g., get image)
    cmd = bytearray([0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x03, 0x01, 0x00, 0x05])
    ser.write(cmd)
    time.sleep(0.1)
    response = ser.read(12)
    print("Response:", response.hex())
except serial.SerialException as e:
    print(f"Error: {e}")
finally:
    if 'ser' in locals():
        ser.close()