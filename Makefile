# CYD Network Sniffer — Build, Flash & Training Shortcuts
#
# Usage:
#   make build          Build firmware
#   make flash          Build + flash to ESP32
#   make monitor        Open serial monitor
#   make fm             Flash + monitor (most common)
#   make train-nn       Train dense NN (default)
#   make train-lstm     Train LSTM hybrid (window=5)
#   make train-rf       Train random forest baseline
#   make ml-copy		Copy ML model from output/ to src/ directory
#   make labels         Generate labels from feature data
#   make clean          Clean build artifacts
#
# Override defaults:
#   make flash PORT=/dev/cu.usbserial-1234
#   make train-lstm WINDOW=10 EPOCHS=200
#   make train-nn BALANCE="anomaly device_type"

# ── Configuration ── #

ENV        := cyd-sniffer
BAUD       := 115200
PORT       := $(shell ls /dev/cu.* 2>/dev/null | grep "/dev/cu.usbserial-")
VENV       := .sniff-env
PY         := $(VENV)/bin/python
DATA_DIR   := training/data
OUTPUT_DIR := training/output
EPOCHS     ?= 100
WINDOW     ?= 5
BALANCE    ?= anomaly protocol device_type

# ── Firmware ── #

.PHONY: build flash monitor fm clean

build:
	pio run -e $(ENV)

flash: _check_port
	pio run -e $(ENV) -t upload --upload-port $(PORT)

monitor: _check_port
	pio device monitor -p $(PORT) -b $(BAUD)

fm: flash monitor

clean:
	pio run -e $(ENV) -t clean

# ── Training ── #

.PHONY: train-nn train-lstm train-gru train-rnn train-rf labels copy

train-nn:
	$(PY) training/train_model.py \
		--data_dir $(DATA_DIR) \
		--output_dir $(OUTPUT_DIR) \
		--model nn \
		--epochs $(EPOCHS) \
		--balance $(BALANCE)

train-lstm:
	$(PY) training/train_model.py \
		--data_dir $(DATA_DIR) \
		--output_dir $(OUTPUT_DIR) \
		--model lstm_lr \
		--window_size $(WINDOW) \
		--epochs $(EPOCHS) \
		--balance $(BALANCE)

train-gru:
	$(PY) training/train_model.py \
		--data_dir $(DATA_DIR) \
		--output_dir $(OUTPUT_DIR) \
		--model gru_lr \
		--window_size $(WINDOW) \
		--epochs $(EPOCHS) \
		--balance $(BALANCE)

train-rnn:
	$(PY) training/train_model.py \
		--data_dir $(DATA_DIR) \
		--output_dir $(OUTPUT_DIR) \
		--model rnn_lr \
		--window_size $(WINDOW) \
		--epochs $(EPOCHS) \
		--balance $(BALANCE)

train-rf:
	$(PY) training/train_model.py \
		--data_dir $(DATA_DIR) \
		--output_dir $(OUTPUT_DIR) \
		--model rf \
		--balance $(BALANCE)

labels:
	$(PY) training/generate_labels.py \
		--data_dir $(DATA_DIR)

ml-copy:
	@echo "Copying model artifacts to src/..."
	cp $(OUTPUT_DIR)/sniffer_model.h src/
	cp $(OUTPUT_DIR)/scaler_params.h src/
	cp $(OUTPUT_DIR)/label_mappings.h src/
	@echo "Done. Run 'make flash' to upload."

# ── Helpers ── #

.PHONY: _check_port

_check_port:
	@test -n  "$(PORT)" && echo "\n$(PORT)\n" || (echo "\nNo serial port found. Plug in the CYD and retry.\n")