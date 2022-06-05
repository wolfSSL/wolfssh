set(srcs main.c ssh_server.c uart_helper.c uart_helper.c wifi.c ssh_server_config.c enc28j60_helper.c int_to_string.c tx_rx_buffer.c)

idf_component_register(
                       SRCS "${srcs}"
                       INCLUDE_DIRS "."
                       PRIV_INCLUDE_DIRS)
