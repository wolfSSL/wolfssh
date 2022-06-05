wolfSSH ESP32 component

This is a static copy for demonstration purposes only.

### Troubleshooting


#### Error undefined reference to `wc_GenerateSeed' libwolfssh.a(random.c.obj) 

This is usaually a mis-configured `user_settings.h` in `components\wolfssh\include`.
