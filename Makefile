CC      = gcc
CFLAGS  = -Wall -Wextra -I./include
LDFLAGS = -L/usr/lib/x86_64-linux-gnu -l:libmsquic.so.2 -lpthread -lcrypto

BIN_DIR  = bin
CERT_DIR = certs
CERT_KEY = $(CERT_DIR)/server.key
CERT_CRT = $(CERT_DIR)/server.crt
WRAPPER  = src/shared/msquic_wrapper.c
SQMP     = src/shared/sqmp.c

.PHONY: all clean

all: $(BIN_DIR)/server $(BIN_DIR)/client

$(CERT_CRT) $(CERT_KEY):
	mkdir -p $(CERT_DIR)
	openssl req -x509 -newkey rsa:2048 -keyout $(CERT_KEY) -out $(CERT_CRT) \
	    -days 365 -nodes -subj "/CN=localhost"

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/server: src/server/server.c $(WRAPPER) $(SQMP) \
                   $(CERT_CRT) $(CERT_KEY) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ src/server/server.c $(WRAPPER) $(SQMP) $(LDFLAGS)

$(BIN_DIR)/client: src/client/client.c $(WRAPPER) $(SQMP) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ src/client/client.c $(WRAPPER) $(SQMP) $(LDFLAGS)

clean:
	rm -f $(BIN_DIR)/server $(BIN_DIR)/client
