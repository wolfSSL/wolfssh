# enc28j60

If the ENS28J60 source files are not in the `components` directory of the ESP-IDF, the [CMakeLists.txt](../../CMakeLists.txt) will try to copy them. See `cmake .`

Otherwise copy the files manually:

```
enc28j60.h
esp_eth_enc28j60.h
esp_eth_mac_enc28j60.c
esp_eth_phy_enc28j60.c
```