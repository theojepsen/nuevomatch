/*
 * MIT License
 * Copyright (c) 2019 Alon Rashelbach
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <list>
#include <vector>

#include <logging.h>
#include <object_io.h>
#include <cut_split.h>
#include <tuple_merge.h>
#include <serial_nuevomatch.h>
#include <nuevomatch_config.h>
#if 1
//#include "nuevomatch_64_classifier.h"
//#include "nuevomatch_64_classifier_1krules.h"
#include "nuevomatch_64_classifier_100rules.h"
#else
char nuevomatch_64_classifier[] = {0};
#endif

#define USE_LNIC false

#if USE_LNIC
#include "lnic.h"
#endif

// Expected address of the load generator
uint64_t load_gen_ip = 0x0a000001;

extern "C" {
    extern int _end;
    char* data_end = (char*)&_end + 16384*4;
    extern void sbrk_init(long int* init_addr);
    extern void __libc_init_array();
    extern void __libc_fini_array();
}

#if USE_LNIC
void send_startup_msg(int cid, uint64_t context_id) {
  uint64_t app_hdr = (load_gen_ip << 32) | (0 << 16) | (2*8);
  uint64_t cid_to_send = cid;
  lnic_write_r(app_hdr);
  lnic_write_r(cid_to_send);
  lnic_write_r(context_id);
}
#endif // USE_LNIC


/**
 * @brief Main entry point
 */
int main(int argc, char** argv) {

	// Set configuration for NuevoMatch
	NuevoMatchConfig config;
	config.num_of_cores = 1;
	config.max_subsets = 1;
	config.start_from_iset = 0;
	config.disable_isets = false;
	config.disable_remainder = false;
	config.disable_bin_search = false;
	config.disable_validation_phase = false;
	config.disable_all_classification = false;
	//config.force_rebuilding_remainder = true;
	config.force_rebuilding_remainder = false;
  config.arbitrary_subset_clore_allocation = nullptr;

#if 1
	const char* remainder_type = "cutsplit";
	uint32_t binth = 8;
	uint32_t threshold = 25;
  config.remainder_classifier = new CutSplit(binth, threshold);
#else
	const char* remainder_type = "tuplemerge";
  config.remainder_classifier = new TupleMerge();
#endif
	config.remainder_type = remainder_type;

  SerialNuevoMatch<1>* classifier = new SerialNuevoMatch<1>(config);

	// Read classifier file to memory
	//ObjectReader classifier_handler("nuevomatch_64.classifier");
	ObjectReader classifier_handler(nuevomatch_64_classifier, sizeof(nuevomatch_64_classifier));

	// Load nuevomatch
	// This will work for both classifiers without remainder classifier set
	// and classifiers with remainder classifiers set
	classifier->load(classifier_handler);

  // Read the textual trace file

#if 0
  messagef("Reading trace file...");
  const char* trace_filename = "trace";
  uint32_t num_of_packets;
  vector<uint32_t> arbitrary_fields;
  trace_packet* trace_packets = read_trace_file(trace_filename, arbitrary_fields, &num_of_packets);
  if (!trace_packets) {
    throw error("error while reading trace file");
  }
#else
  uint32_t num_of_packets = 10;
  trace_packet trace_packets[10];
  trace_packets[0].header = {532746804, 3397109384, 43204, 1521,  6, 0}; trace_packets[0].match_priority = 94;
  trace_packets[1].header = {520899175, 3396744005, 33500, 1715,  6, 0}; trace_packets[1].match_priority = 73;
  trace_packets[2].header = {525102834, 3396784787, 26901, 6790,  6, 0}; trace_packets[2].match_priority = 85;
  trace_packets[3].header = {475623671, 3396388276, 10205, 5631,  6, 0}; trace_packets[3].match_priority = 34;
  trace_packets[4].header = {492908153, 3396476695, 11394, 19856, 6, 0}; trace_packets[4].match_priority = 9;
  trace_packets[5].header = {520346879, 3396746798, 14598, 20,    6, 0}; trace_packets[5].match_priority = 76;
  trace_packets[6].header = {496792388, 3396337836, 8702,  1711,  6, 0}; trace_packets[6].match_priority = 26;
  trace_packets[7].header = {533223626, 219940546,  47855, 1705,  6, 0}; trace_packets[7].match_priority = 93;
  trace_packets[8].header = {492908153, 3396476695, 43418, 19856, 6, 0}; trace_packets[8].match_priority = 9;
  trace_packets[9].header = {520382556, 3396746440, 6686,  2121,  6, 0}; trace_packets[9].match_priority = 77;
#endif
  messagef("Total %u packets in trace", num_of_packets);

  // Limit the number of packets
  uint32_t start_packet = 0;
  uint32_t end_packet   = -1;
  if (end_packet > num_of_packets) end_packet = num_of_packets;

  //uint64_t start_cycles, delta_cycles;

#if !USE_LNIC
  // Warm cache
  uint32_t warm_repetitions = 5;
  for (uint32_t r=0; r<warm_repetitions; ++r) {
    messagef("Iteration %u...", r);
    //start_cycles = rdcycle();
    for (uint32_t i=start_packet; i<end_packet; ++i) {
      classifier_output_t out = classifier->classify(trace_packets[i].get());
      if ((uint32_t)out.action != trace_packets[i].match_priority) {
					warningf("packet %u does not match!. Got: %u, expected: %u",
							i, out.action, trace_packets[i].match_priority);
      }
    }
    classifier->reset_counters();
    //delta_cycles = rdcycle() - start_cycles;
    //printf("Latency: %ld cycles total, %ld cycles/packet\n", delta_cycles, delta_cycles/num_of_packets);
  }

 	// Perform the experiment, repeat X times
 	uint32_t time_to_repeat = 10;
 	messagef("Repeating experiment %u times", time_to_repeat);

 	for (uint32_t i=0; i<time_to_repeat; ++i) {
    messagef("Starting trace test for classifier with %u packets...", (end_packet-start_packet));

    // Reset counters
    classifier->reset_counters();
    //start_cycles = rdcycle();
    classifier->start_performance_measurement();
    // Run the lookup
    for (uint32_t i=start_packet; i<end_packet; ++i) {
      classifier_output_t out = classifier->classify(trace_packets[i].get());
      if (out.action != 0) continue;
      if ((uint32_t)out.action != trace_packets[i].match_priority) {
					warningf("packet %u does not match!. Got: %u, expected: %u",
							i, out.action, trace_packets[i].match_priority);
      }
    }
    //delta_cycles = rdcycle() - start_cycles;
    //printf("Latency: %ld cycles total, %ld cycles/packet\n", delta_cycles, delta_cycles/num_of_packets);

    classifier->stop_performance_measurement();

 		bool mod_print = true;
 		if (mod_print) {
 			messagef("Classifier Information:");
 			classifier->print(3);
 		}
 	}
#else


  int cid = 0;
  send_startup_msg(cid, 0);

  uint64_t app_hdr, sent_time, service_time, class_meta;
#define HEADER_WORDS 3
  uint64_t headers[HEADER_WORDS];
  while (1) {
    lnic_wait();
    app_hdr = lnic_read();
    //printf("[%d] --> Received msg of length: %u bytes\n", cid, (uint16_t)app_hdr);
    service_time = lnic_read();
    sent_time = lnic_read();
    class_meta = lnic_read();

    //for (int i = 0; i < HEADER_WORDS; i++) headers[i] = lnic_read();
    headers[0] = lnic_read();
#if HEADER_WORDS > 1
    headers[1] = lnic_read();
#endif
#if HEADER_WORDS > 2
    headers[2] = lnic_read();
#endif
#if HEADER_WORDS > 3
#error "Add more unrolled iterations for both lread() and lwrite()"
#endif

    classifier_output_t out = classifier->classify((uint32_t*)headers);
    int action = out.action;
    //int action = config.remainder_classifier->classify_sync((uint32_t*)headers, -1);
    uint32_t trace_idx = class_meta >> 32;
    class_meta = ((uint64_t)trace_idx << 32) | ((uint32_t)action);

    lnic_write_r((app_hdr & (IP_MASK | CONTEXT_MASK)) | (8 + 8 + 8 + (HEADER_WORDS * 8)));
    lnic_write_r(service_time);
    lnic_write_r(sent_time);
    lnic_write_r(class_meta);
    //for (int i = 0; i < HEADER_WORDS; i++) lnic_write_r(headers[i]);
    lnic_write_r(headers[0]);
#if HEADER_WORDS > 1
    lnic_write_r(headers[1]);
#endif
#if HEADER_WORDS > 2
    lnic_write_r(headers[2]);
#endif
    lnic_msg_done();
	}
#endif

 	delete classifier;
}

#if USE_LNIC
extern "C" {
bool is_single_core() { return false; }
int core_main(int argc, char** argv, int cid, int nc) {
  (void)nc;

  uint64_t context_id = 0;
  uint64_t priority = 0;
  lnic_add_context(context_id, priority);

  if (cid > 0) {
    send_startup_msg(cid, context_id);
    return EXIT_SUCCESS;
  }

  // Setup the C++ libraries
  sbrk_init((long int*)data_end);
  atexit(__libc_fini_array);
  __libc_init_array();

  return main(argc, argv);
}
}
#endif // USE_LNIC
