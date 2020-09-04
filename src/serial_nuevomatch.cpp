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

#include <set>
#include <string>
#include <vector>
#include <list>
#include <queue>
#include <algorithm>
#include <string.h>

#include <object_io.h>
#include <cpu_core_tools.h>

#include <array_operations.h>
#include <string_operations.h>
#include <serial_nuevomatch.h>

/**
 * @brief Initiate a new SerialNuevoMatch instance.
 * @param config The configuration for SerialNuevoMatch
 */
template <uint32_t N>
SerialNuevoMatch<N>::SerialNuevoMatch(NuevoMatchConfig config) :
	_configuration(config), _isets(nullptr),
	_last_iset_idx(0),
	_num_of_isets(0),_num_of_rules(0),
	_size(0), _build_time(0),
	_pack_buffer(nullptr), _pack_size(0),
  _packet_counter(0),
  _my_isets(), _remainder(nullptr) { };

template <uint32_t N>
SerialNuevoMatch<N>::~SerialNuevoMatch() {
  for (auto iset :_my_isets) {
    delete iset;
  }
  delete _remainder;
}

/**
 * @brief Creates this from a memory location
 * @param object An object-reader instance
 */
template <uint32_t N>
void SerialNuevoMatch<N>::load(ObjectReader& reader) {

	// Used for packing
	_pack_buffer = new uint8_t[reader.size()];
	_pack_size = reader.size();
	memcpy(_pack_buffer, reader.buffer(), reader.size());

	// Read static information
	reader 	>> _num_of_isets >> _num_of_rules
			>> _size >> _build_time;

	// The size is measured by the iSets, and not by what was packed
	// Reason: support dynamic size for dynamic iSets
	_size = 0;

	// Show general information
	if (_configuration.disable_bin_search) {
		loggerf("Disabling binary search in all iSets");
	}
	if (_configuration.disable_remainder) {
		loggerf("Disabling remainder classifier");
	}
	if (_configuration.disable_validation_phase) {
		loggerf("Disabling validation phase in all iSets");
	}
	if (_configuration.disable_all_classification) {
		loggerf("Disabling classification");
	}

	// Check configuration error
	if (!_configuration.disable_remainder && !_configuration.remainder_classifier) {
		throw error("Remainder classifier is enabled but is not set");
	}

	// Load all subsets from file
	load_subsets(reader);

	// Load the remainder classifier
	load_remainder(reader);

	// Group subsets to groups, initialize workers
	group_subsets_to_cores();

}

/**
 * @brief Packs this to byte array
 * @returns An object-packer with the binary data
 */
template <uint32_t N>
ObjectPacker SerialNuevoMatch<N>::pack() const {

	// Pack the remainder classifier
	ObjectPacker remainder_packer = _configuration.remainder_classifier->pack();

	// Pack this
	ObjectPacker output;
	output.push(_pack_buffer, _pack_size);
	output << remainder_packer;

	return output;
}

/**
 * @brief Resets the all classifier counters
 */
template <uint32_t N>
void SerialNuevoMatch<N>::reset_counters() {
  _packet_counter = 0;
}

/**
 * @brief Advance the packet counter. Should be used when skipping
 * classification of packets, such as with caches.
 */
template <uint32_t N>
void SerialNuevoMatch<N>::advance_counter() {
	_packet_counter++;
}

/**
 * @brief Starts the performance measurement of this
 */
template <uint32_t N>
void SerialNuevoMatch<N>::start_performance_measurement() {
	clock_gettime(CLOCK_MONOTONIC, &start_time);
}

/**
 * @brief Stops the performance measurement of this
 */
template <uint32_t N>
void SerialNuevoMatch<N>::stop_performance_measurement() {
	clock_gettime(CLOCK_MONOTONIC, &end_time);
}


/**
 * @brief Prints statistical information
 * @param verbose Set the verbosity level of printing
 */
template <uint32_t N>
void SerialNuevoMatch<N>::print(uint32_t verbose) const {

	// High verbosity
	if (verbose > 2) {

		// Print the errors of all RQRMI
		for (uint32_t i=_configuration.start_from_iset; i<_last_iset_idx; ++i) {
			SimpleLogger::get() << "Error list for iSet " << i << ": [";
			auto&& error_list = _isets[i]->get_error_list();
			bool first = true;
			for (auto it : error_list) {
				if (!first) SimpleLogger::get() << ", ";
				SimpleLogger::get() << it;
				first = false;
			}
			SimpleLogger::get() << "]" << SimpleLogger::endl();
		}
		// Print expected errors
		for (uint32_t i=_configuration.start_from_iset; i<_last_iset_idx; ++i) {
			message_s("Expected error for iSet " << i << ": "
				 << _isets[i]->get_expected_error());
		}
	}

	// Measure performance
	double total_usec = (double)((end_time.tv_sec * 1e9 + end_time.tv_nsec) -
						  (start_time.tv_sec * 1e9 + start_time.tv_nsec)) / 1e3;

	messagef("Performance: total time %.3lf usec. Average time: %.3lf usec per packet.",
			total_usec, total_usec / _packet_counter);

	// Medium verbosity
	if (verbose > 1) {
		if (!_configuration.disable_remainder) {
			messagef("Remainder classifier total size: %u bytes", this->_configuration.remainder_classifier->get_size());
		}
	}

	// Max verbosity
	if (verbose > 3 && !_configuration.disable_remainder) {
		messagef("Remainder classifier information");
		this->_configuration.remainder_classifier->print(verbose-1);
	}
}

/**
 * @brief Loads all subsets (iSets/Remainder) from file
 * @param reader An object-reader with binary data
 */
template <uint32_t N>
void SerialNuevoMatch<N>::load_subsets(ObjectReader& reader) {

	// Lists to populate available iSets and any remainder rules
	_remainder_rules.clear();

	// Statistics
	uint32_t iset_rule_count=0;

	_isets = new IntervalSet<N>*[_num_of_isets];

	// Populate lists based on configuration
	for (uint32_t i=0; i<_num_of_isets; ++i) {

		// Get the handler of the next stored iSet
		ObjectReader sub_reader;
		reader >> sub_reader;

		// Read the current iSet
		IntervalSet<N>* iset = new IntervalSet<N>(i);
		iset->load(sub_reader);

		bool skip_current_iset =
				// Skip the current iSet in case the maximum number of iSets is limited
				((_configuration.max_subsets >= 0) && ((uint32_t)_configuration.max_subsets <= i)) ||
				// Skip the current iSet in case the minimal iSet number if limited
				(_configuration.start_from_iset > i) ||
				// The iSet field index should be skipped
				((_configuration.arbitrary_fields.size() > 0) &&
						(std::find(	_configuration.arbitrary_fields.begin(),
									_configuration.arbitrary_fields.end(),
									iset->get_field_index())
						 == _configuration.arbitrary_fields.end())
				);

		// In case the current iSet is valid but should not run
		if (!skip_current_iset && _configuration.disable_isets) {
			auto rules = iset->extract_rules();
			loggerf("Created a disabled iSet (%u) with %lu rules.", i, rules.size());
			_isets[i] = nullptr;
			delete iset;
		}
		// In case the current iSet should be skipped
		else if (skip_current_iset) {

			auto rules = iset->extract_rules();
			_remainder_rules.insert(_remainder_rules.end(), rules.begin(), rules.end());

			_isets[i] = nullptr;
			delete iset;

			loggerf("Skipping iSet %u. Extracted %lu rules.", i, rules.size());
		}
		// In case the current iSet is valid, and the disable-isets option is disabled
		else {
			_isets[i] = iset;

			// In case the field list is reconfigured
			if (_configuration.arbitrary_fields.size() > 0) {
				iset->rearrange_field_indices(_configuration.arbitrary_fields);
			}

			// Update statistics
			iset_rule_count += iset->size();
			_size += iset->get_size();
		}
	}

	// Read the predefined remainder rule-set, add to remainder
	ObjectReader db_reader(reader.buffer(), reader.size()); // TODO This is ugly, change packing to be using sub-reader
	std::list<openflow_rule> predefined_remainder = load_rule_database(db_reader);
	_remainder_rules.insert(_remainder_rules.end(), predefined_remainder.begin(), predefined_remainder.end());

	// Sort remainder rules by priority
	_remainder_rules.sort();
	uint32_t net_total_rules = (iset_rule_count+_remainder_rules.size());
	loggerf("Total rules after removing validation phase duplicates: %u", net_total_rules);

	// Print iSet coverage status
	for (uint32_t i=0; i<_num_of_isets; ++i) {
		if (_isets[i] == nullptr) continue;
		loggerf("iSet %u holds %u rules (coverage: %.2f) for field %u with RQRMI size of %u bytes",
				i, _isets[i]->size(), (scalar_t)_isets[i]->size() / net_total_rules * 100,
				_isets[i]->get_field_index(), _isets[i]->get_size());
	}

	// Print coverage status
	loggerf("SerialNuevoMatch total coverage: %.2f%%", (double)iset_rule_count/net_total_rules*100);
}

/**
 * @brief Loads the remainder classifier based on subset configuration and input file
 * @param buffer The input buffer
 * @param size The buffer size in bytes
 */
template <uint32_t N>
void SerialNuevoMatch<N>::load_remainder(ObjectReader& reader) {

	ObjectReader sub_reader;

	// In case the remainder classifier should be avoided
	if (_configuration.disable_remainder) {
		delete _configuration.remainder_classifier;
		_configuration.remainder_classifier = nullptr;
		return;
	}

	// In case the remainder classifier is external, do not change it
	if (_configuration.external_remainder) {
		if (_configuration.remainder_classifier == nullptr) {
			throw error("Remainder classifier was set as external, but is not available");
		}
		return;
	}

	// In case at least on iSet is missing, the classifier should be built
	bool rebuild_remainder = _configuration.force_rebuilding_remainder;
	for (uint32_t i=0; i<_num_of_isets;++i) {
		if (_isets[i] == nullptr) {
			rebuild_remainder = true;
			break;
		}
	}

        // Build remainder classifier from temporary rule-set
        if (rebuild_remainder) {
                sub_reader = build_remainder();
        }
        // Load the sub-reader from reader
        else {
                try {
                        reader >> sub_reader;
                } catch (const exception& e) {
                        throw error("Error while extracting remainder classifier: " << e.what());
                }
        }

        // Load classifier from sub-reader
        try {
                _configuration.remainder_classifier->load(sub_reader);
                return;
        } catch (const exception& e) {
                warning("Error while loading remainder classifier: " << e.what());
        }

        // Try to recover
        loggerf("Recovering by rebuilding remainder classifier");
        sub_reader = build_remainder();
        try {   
                _configuration.remainder_classifier->load(sub_reader);
                return;
        } catch (const exception& e) {
                error("Error while loading remainder classifier: " << e.what());
        }
}


/**
 * @brief Manually build remainder classifier
 */
template <uint32_t N>
ObjectReader SerialNuevoMatch<N>::build_remainder() {
        loggerf("Manually building remainder classifier (remainder holds %lu rules)", _remainder_rules.size());
        // Building new classifier might thrash cash.
        // Therefore, the building is done using a temporary object
        GenericClassifier* gc;
        if (_configuration.remainder_type == "cutsplit") {
                gc = new CutSplit(24, 8);
        } else if (_configuration.remainder_type == "tuplemerge") {
                gc = new TupleMerge();
        } else {
                throw errorf("NuevoMatch cannot rebuild a remainder classifier of type %s", _configuration.remainder_type);
        }

        gc->build(_remainder_rules);
        // Pack classifier into reader
        ObjectReader output = ObjectReader(gc->pack());
        delete gc;
        return output;
}


/**
 * @brief Group the subsets based on their size (load-balance), and assign them to cores
 * @throws In case no valid subsets are available
 */
template <uint32_t N>
void SerialNuevoMatch<N>::group_subsets_to_cores() {

	// Create a list of all subset classifiers based on availability
	std::vector<NuevoMatchSubset<N>*> subsets;

	// Add iSets
	for (uint32_t i=0; i<_num_of_isets;++i) {
		if (_isets[i] != nullptr) {
			subsets.push_back(_isets[i]);
		}
	}

	// Add remainder classifier
	if (_configuration.remainder_classifier != nullptr) {
		subsets.push_back(new NuevoMatchRemainderClassifier<N>(_configuration.remainder_classifier));
	}

	if (subsets.size() == 0) {
		throw error("Classifier has no valid subsets");
	}

	// Sort subsets based on the number of rules they hold (high to low)
	std::sort(subsets.begin(), subsets.end(),
			[](const NuevoMatchSubset<N>* a, const NuevoMatchSubset<N>* b) {
				return a->get_size() > b->get_size();
			});

	// Load balance between all classifiers and workers
	std::list<NuevoMatchSubset<N>*> classifier_list[_configuration.num_of_cores];

	// There is not an arbitrary allocation, allocate based on size
  // Store the size in bytes used in each core
  uint32_t core_size[_configuration.num_of_cores];
  for (uint32_t i=0; i<_configuration.num_of_cores; ++i) {
    core_size[i] = 0;
  }

  for (auto it : subsets) {
    uint32_t current = 0, size_min=core_size[0];
    // Choose the core with minimum size
    for (uint32_t i=0; i<_configuration.num_of_cores; ++i) {
      if (core_size[i] < size_min) {
        current = i;
        size_min = core_size[i];
      }
    }
    // Add the current subset to the core
    classifier_list[current].push_back(it);
    core_size[current] += it->get_size();
  }

	// The current thread will run a serial worker
	for (auto it : classifier_list[0]) {
		add_subset(*it);
	}

	// Print status of all workers
	for (uint32_t i=0; i<_configuration.num_of_cores; ++i) {

		// Calculate KB for the current worker
		uint32_t size = 0;
		for (auto it : classifier_list[i]) {
			size += it->get_size();
		}

		string_operations::convertor_to_string<NuevoMatchSubset<N>*> classifier_to_string =
				[](NuevoMatchSubset<N>* const& item) -> string { return item->to_string(); };
		string subset_string = string_operations::join(classifier_list[i], " ", classifier_to_string);

		// Print status of serial worker
		logger("SerialNuevoMatch worker 0 holds: {" << subset_string << "} of total " << size << " KB.");
	}

}

template <uint32_t N>
classifier_output_t SerialNuevoMatch<N>::classify(const uint32_t* header) {
  _packet_counter++;
  WorkBatch<const uint32_t*, N> packets {header};

  // Initiate output
  ActionBatch<N> output;
  for (uint32_t i=0; i<N; ++i) {
    output[i] = {-1, -1};
  }

  // In case no classification should be done at all
  if (_configuration.disable_all_classification) {
    return output[0];
  }

  // In case any iSets exist in this
  uint32_t num_of_isets = _my_isets.size();
  if (num_of_isets > 0) {
    //printf("num_of_isets=%d\n", num_of_isets);
  }
  if (num_of_isets > 0) {

    IntervalSetInfoBatch<N> info[num_of_isets];

    // Perform inference on all iSets
    // -----------------------------
    for (uint32_t k=0; k<num_of_isets; ++k) {
      info[k] = _my_isets[k]->rqrmi_search(packets);
    }

    // Perform secondary search
    // -----------------------------
    // Note: The search is done across all iSets for exploiting memory parallelism
    // (Unlike common sense, by which secondary search should be done one iSet after another)

    if (_configuration.disable_bin_search) {
      return output[0];
    }

    // For each packet in batch
    for (uint32_t i=0; i<N; ++i) {

      scalar_t key[num_of_isets];
      uint32_t position[num_of_isets], u_bound[num_of_isets], l_bound[num_of_isets];
      uint32_t max_error = 0;

      // Initiate all variables from all iSets
      for (uint32_t k=0; k<num_of_isets; ++k) {
        uint32_t error = info[k][i].rqrmi_error;
        // Used for debugging
#if defined CUSTOM_ERROR_VALUE
        error = CUSTOM_ERROR_VALUE;
#endif
        // Update all variables
        key[k] = info[k][i].rqrmi_input;
        position[k] = info[k][i].rqrmi_output * _my_isets[k]->size();
        u_bound[k] = std::min(_my_isets[k]->size()-1, position[k]+error);
        l_bound[k] = std::max(0, (int)position[k]-(int)error);
        max_error = std::max(error, max_error);
      }

      // In case of binary search (default)
#ifndef LINEAR_SEARCH
      uint32_t current_value[num_of_isets], next_value[num_of_isets];

      // Perform binary search
      do {

        // Fetch index database information from memory
        for (uint32_t k=0; k<num_of_isets; ++k) {
          current_value[k] = _my_isets[k]->get_index(position[k]) <= key[k];
          next_value[k] = _my_isets[k]->get_index(position[k]+1) > key[k];
        }

        // Calculate the next position per packet in batch
        for (uint32_t k=0; k<num_of_isets; ++k) {
          if (current_value[k] & next_value[k]) {
            // Do nothing
          } else if (current_value[k]) {
            l_bound[k] = position[k];
            position[k]=(l_bound[k]+u_bound[k]);
            position[k]=(position[k]>>1)+(position[k]&0x1); // Ceil
          } else if (info[k][i].valid) {
            u_bound[k] = position[k];
            position[k]=(l_bound[k]+u_bound[k])>>1; // Floor
          }
        }

        // Update error
        max_error >>= 1;
      } while (max_error > 0);
      // In case of linear search (used for debugging)
#else
      for (uint32_t k=0; k<num_of_isets; ++k) {
        for (position[k]=l_bound[k]; position[k]<u_bound[k]; ++position[k]) {
          uint32_t current_value = _my_isets[k]->get_iset()->get_index(position[k]) <= key[k];
          uint32_t next_value = _my_isets[k]->get_iset()->get_index(position[k]+1) > key[k];
          if (current_value & next_value) {
            break;
          }
        }
      }
#endif

      // Perform validation phase across all iSets
      // -----------------------------
      // Note: The validation is done across all iSets for exploiting memory parallelism
      // (Unlike common sense, by which validation should be done one iSet after another)

      if (_configuration.disable_validation_phase) continue;
      // Skip invalid packets
      if (packets[i] == nullptr) continue;

      // Take the largest priority out of all iSets
      for (uint32_t k=0; k<num_of_isets; ++k) {
        classifier_output_t current = _my_isets[k]->do_validation(packets[i], position[k]);
        if ((uint32_t)current.priority < (uint32_t)output[i].priority) {
          output[i] = current;
        }
      }


    } // For Packet in batch
  } // If any iSet exists


  // Perform classification on remainder classifier
  if (!_configuration.disable_remainder &&
      _configuration.remainder_classifier != nullptr)
  {
    output = _remainder->classify(packets, output);
  }

  return output[0];
}

template <uint32_t N>
void SerialNuevoMatch<N>::add_subset(NuevoMatchSubset<N>& subset) {
  // What is the dynamic type the subset is holding?
  typename NuevoMatchSubset<N>::dynamic_type_t type = subset.get_type();
  // In case of an iSet, try to static-cast the subset to iset and add it
  if (type == NuevoMatchSubset<N>::dynamic_type_t::ISET) {
    IntervalSet<N>* iset = static_cast<IntervalSet<N>*>(&subset);
    if (iset == nullptr) {
      throw error("Cannot convert subset to its dynamic type iSet");
    }
    this->_my_isets.push_back(iset);
  }
  // In case of an adapter to remainder classifier, set it as the remainder
  // only if the static-cast is a success and there is not an existing
  // raminder in this
  else if (type == NuevoMatchSubset<N>::dynamic_type_t::REMAINDER) {
    NuevoMatchRemainderClassifier<N>* remainder =
      static_cast<NuevoMatchRemainderClassifier<N>*>(&subset);
    if (remainder != nullptr && _remainder == nullptr){
      this->_remainder = remainder;
    } else if (_remainder != nullptr) {
      throw error("Cannot add two remainder classifiers to the same group");
    } else {
      throw error("Cannot convert subset to its dynamic type remainder-classifier");
    }
  }
}

// Initiate template with custom batch sizes
template class SerialNuevoMatch<1>;
