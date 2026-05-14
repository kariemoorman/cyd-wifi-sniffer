#pragma once

#include "ring_buffer.h"

void sniffer_init(RingBuffer* rb);
void sniffer_start();
void sniffer_stop();
void sniffer_set_channel(int channel);
int  sniffer_get_channel();
bool sniffer_is_running();
void sniffer_set_auto_hop(bool enabled);
bool sniffer_is_auto_hop();
void sniffer_tick();