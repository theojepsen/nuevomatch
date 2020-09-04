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
	ObjectReader classifier_handler("nuevomatch_64.classifier");

	// Load nuevomatch
	// This will work for both classifiers without remainder classifier set
	// and classifiers with remainder classifiers set
	classifier->load(classifier_handler);

  // Read the textual trace file

  messagef("Reading trace file...");
  const char* trace_filename = "trace";
  uint32_t num_of_packets;
  vector<uint32_t> arbitrary_fields;
  trace_packet* trace_packets = read_trace_file(trace_filename, arbitrary_fields, &num_of_packets);
  if (!trace_packets) {
    throw error("error while reading trace file");
  }
  messagef("Total %u packets in trace", num_of_packets);

  // Limit the number of packets
  uint32_t start_packet = 0;
  uint32_t end_packet   = -1;
  if (end_packet > num_of_packets) end_packet = num_of_packets;

  // Warm cache
  uint32_t warm_repetitions = 5;
  for (uint32_t r=0; r<warm_repetitions; ++r) {
    messagef("Iteration %u...", r);
    for (uint32_t i=start_packet; i<end_packet; ++i) {
      classifier_output_t out = classifier->classify(trace_packets[i].get());
      if ((uint32_t)out.action != trace_packets[i].match_priority) {
					warningf("packet %u does not match!. Got: %u, expected: %u",
							i, out.action, trace_packets[i].match_priority);
      }
    }
    classifier->reset_counters();
  }

 	// Perform the experiment, repeat X times
 	uint32_t time_to_repeat = 10;
 	messagef("Repeating experiment %u times", time_to_repeat);

 	for (uint32_t i=0; i<time_to_repeat; ++i) {
    messagef("Starting trace test for classifier with %u packets...", (end_packet-start_packet));

    // Reset counters
    classifier->reset_counters();

    classifier->start_performance_measurement();
    // Run the lookup
    for (uint32_t i=start_packet; i<end_packet; ++i) {
      classifier_output_t out = classifier->classify(trace_packets[i].get());
      if ((uint32_t)out.action != trace_packets[i].match_priority) {
					warningf("packet %u does not match!. Got: %u, expected: %u",
							i, out.action, trace_packets[i].match_priority);
      }
    }

    classifier->stop_performance_measurement();

 		bool mod_print = true;
 		if (mod_print) {
 			messagef("Classifier Information:");
 			classifier->print(3);
 		}
 	}

 	delete classifier;
}
