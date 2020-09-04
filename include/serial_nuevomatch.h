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
#pragma once

#include <time.h>
#include <bits/stdc++.h> // UINT_MAX
#include <set>
#include <array>

#include <basic_types.h>

#include <nuevomatch_base.h>
#include <nuevomatch_config.h>
#include <interval_set.h>

#include <cut_split.h>
#include <tuple_merge.h>
#include <rule_db.h>

/**
 * @brief SerialNuevoMatch packet classifier main class, version 1.0
 *        Supports loading precompiled classifiers and running them.
 *        Supports multiple configurations and environments.
 * @tparam N Number of packets in batch
 */
template <uint32_t N>
class SerialNuevoMatch  {
protected:

	// The configuration for this
	NuevoMatchConfig _configuration;

	// Pointers to all iSets
	IntervalSet<N>** _isets;

	// Configuration for subset classifiers
	uint32_t _last_iset_idx;

	// Hold information
	uint32_t _num_of_isets;
	uint32_t _num_of_rules;
	uint32_t _size;
	uint32_t _build_time;

	// Used for packing
	uint8_t* _pack_buffer;
	uint32_t _pack_size;

  uint32_t _packet_counter;

	// The remainder rules
	std::list<openflow_rule> _remainder_rules;

	// Performance
	struct timespec start_time, end_time;

public:

	/**
	 * @brief Initiate a new NuevoMatch instance.
	 * @param config The configuration for NuevoMatch
	 */
	SerialNuevoMatch(NuevoMatchConfig config);
	virtual ~SerialNuevoMatch();

	/**
	 * @brief Build the classifier data structure
	 * @returns 1 On success, 0 on fail
	 */
	int build(const std::list<openflow_rule>& rule_db) { warning("should be done with Python"); return 0; }

	/**
	 * @brief Packs this to byte array
	 * @returns An object-packer with the binary data
	 */
	ObjectPacker pack() const;

	/**
	 * @brief Creates this from a memory location
	 * @param object An object-reader instance
	 */
	void load(ObjectReader& object);

	/**
	 * @brief Returns the number of rules
	 */
	uint32_t get_num_of_rules() const {
		return _num_of_rules;
	}

	/**
	 * @brief Returns the memory size of this in bytes
	 */
	uint32_t get_size() const {
		return _size;
	}

	/**
	 * @brief Returns the building time of this in milliseconds
	 */
	uint32_t get_build_time() const {
		return _build_time;
	}

	/**
	 * @brief Returns the maximum supported number of fields this can classify
	 */
	virtual const unsigned int get_supported_number_of_fields() const { return UINT_MAX; }

	/**
	 * @brief Starts the performance measurement of this
	 */
	void start_performance_measurement();

	/**
	 * @brief Stops the performance measurement of this
	 */
	void stop_performance_measurement();

	/**
	 * @brief clones this to another instance
	 */
	virtual SerialNuevoMatch* clone() {
		return new SerialNuevoMatch(*this);
	}

  virtual classifier_output_t classify(const uint32_t* header);

	/**
	 * @brief Prints statistical information
	 * @param verbose Set the verbosity level of printing
	 */
	virtual void print(uint32_t verbose=1) const;

	/**
	 * @brief Resets the all classifier counters
	 */
	virtual void reset_counters();
	
	/**
         * @brief Advance the packet counter. Should be used when skipping 
         * classification of packets, such as with caches.
         */
        virtual void advance_counter();

	/**
	 * @brief Returns a string representation of this
	 */
	virtual const std::string to_string() const { return "SerialNuevoMatch"; }


private:

	/**
	 * @brief Loads all subsets (iSets/Remainder) from file
	 * @param reader An object-reader with binary data
	 */
	void load_subsets(ObjectReader& reader);

        /**
         * @brief Manually build remainder classifier
         */
        ObjectReader build_remainder();

	/**
	 * @brief Loads the remainder classifier from file
	 * @param reader An object-reader with binary data
	 */
	void load_remainder(ObjectReader& reader);

	/**
	 * @brief Group the subsets based on their size (load-balance), and assign them to cores
	 * @throws In case no valid subsets are available
	 */
	void group_subsets_to_cores();

	// Explicitly holds pointers to iSets or the remainder classifier
	std::vector<IntervalSet<N>*> _my_isets;
	NuevoMatchRemainderClassifier<N>* _remainder;

  // TODO: this was added while importing code from nuevomatch_worker.h.
  // classify() should be refactored to not the _my_isets that this populates.
	void add_subset(NuevoMatchSubset<N>& subset);
};
