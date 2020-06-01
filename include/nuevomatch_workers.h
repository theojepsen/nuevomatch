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

#include <pipeline_thread.h>

#include <nuevomatch_base.h>
#include <nuevomatch_config.h>
#include <interval_set.h>

/**
 * @brief An abstract class for NuevoMatch worker listener.
 *        The workers publish their results to these listeners.
 * @tparam N The number of packets in each batch
 */
template <uint32_t N>
class NuevoMatchWorkerListener {
public:

	/**
	 * @brief Callback. Invoked by the worker on result
	 * @param info The classifier output generated by the worker
	 * @param worker_idx The worker index
	 * @param batch_id A unique id for the batch
	 */
	virtual void on_new_result(ActionBatch<N> info, uint32_t worker_idx, uint32_t batch_id) = 0;
	virtual ~NuevoMatchWorkerListener() {}
};

/**
 * @brief Abstract class. Holds a group of NuevoMatch subsets.
 *        All subsets in group perform classification serially on the same CPU.
 *        All subsets in group work on the same amount of packets per batch
 * @tparam N Number of packets in batch
 */
template <uint32_t N>
class NuevoMatchWorker {
private:

	// Listeners
	std::vector<NuevoMatchWorkerListener<N>*> _listeners;

	// Worker index
	uint32_t _worker_idx;

protected:

	// Explicitly holds pointers to iSets or the remainder classifier
	std::vector<IntervalSet<N>*> _isets;
	NuevoMatchRemainderClassifier<N>* _remainder;

	// Holds the configuration for NuevoMatch
	NuevoMatchConfig* _configuration;

	// Measure how much time is spent in publish results in us
	double _publish_results_time;

	// A job for the worker
	typedef struct {
		PacketBatch<N> packets;
		uint32_t batch_id;
	} Job;

	/**
	 * @brief Publish the results of this to all listeners
	 */
	void publish_results(ActionBatch<N> info, uint32_t batch_id) {
		struct timespec _start_time, _end_time;
		clock_gettime(CLOCK_MONOTONIC, &_start_time);
		for (auto it : _listeners) {
			it->on_new_result(info, _worker_idx, batch_id);
		}
		clock_gettime(CLOCK_MONOTONIC, &_end_time);
		_publish_results_time += (_end_time.tv_sec - _start_time.tv_sec) * 1e6 +
				(double)(_end_time.tv_nsec - _start_time.tv_nsec) / 1e3;
	}

	/**
	 * @brief Perform classification by all subsets in this.
	 * @param job A batch of N packets
	 * @param args A pointer to an instance of NuevoMatchWorker
	 * @returns A batch of N actions
	 */
	static bool work(Job& job, void* args) {

		// Get the instance
		NuevoMatchWorker* instance = static_cast<NuevoMatchWorker*>(args);

		// Initiate output
		ActionBatch<N> output;
		for (uint32_t i=0; i<N; ++i) {
			output[i] = {-1, -1};
		}

		// In case no classification should be done at all
		if (instance->_configuration->disable_all_classification) {
			instance->publish_results(output, job.batch_id);
			return true;
		}

		// In case any iSets exist in this
		uint32_t num_of_isets = instance->_isets.size();
		if (num_of_isets > 0) {

			IntervalSetInfoBatch<N> info[num_of_isets];

			// Perform inference on all iSets
			// -----------------------------
			for (uint32_t k=0; k<num_of_isets; ++k) {
				info[k] = instance->_isets[k]->rqrmi_search(job.packets);
			}

			// Perform secondary search
			// -----------------------------
			// Note: The search is done across all iSets for exploiting memory parallelism
			// (Unlike common sense, by which secondary search should be done one iSet after another)

			if (instance->_configuration->disable_bin_search) {
				instance->publish_results(output, job.batch_id);
				return true;
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
					position[k] = info[k][i].rqrmi_output * instance->_isets[k]->size();
					u_bound[k] = std::min(instance->_isets[k]->size()-1, position[k]+error);
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
							current_value[k] = instance->_isets[k]->get_index(position[k]) <= key[k];
							next_value[k] = instance->_isets[k]->get_index(position[k]+1) > key[k];
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
							uint32_t current_value = _isets[k]->get_iset()->get_index(position[k]) <= key[k];
							uint32_t next_value = _isets[k]->get_iset()->get_index(position[k]+1) > key[k];
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

				if (instance->_configuration->disable_validation_phase) continue;
				// Skip invalid packets
				if (job.packets[i] == nullptr) continue;

				// Take the largest priority out of all iSets
				for (uint32_t k=0; k<num_of_isets; ++k) {
					classifier_output_t current = instance->_isets[k]->do_validation(job.packets[i], position[k]);
					if ((uint32_t)current.priority < (uint32_t)output[i].priority) {
						output[i] = current;
					}
				}


			} // For Packet in batch
		} // If any iSet exists


		// Perform classification on remainder classifier
		if (!instance->_configuration->disable_remainder &&
			instance->_remainder != nullptr)
		{
			output = instance->_remainder->classify(job.packets, output);
		}

		instance->publish_results(output, job.batch_id);
		return true;
	}

public:

	/**
	 * @brief Initiates this with a pointer to the configuration required by NuevoMatch
	 * @param worker_index A unique index for this
	 * @param configuration A reference to a NuevoMatch configuration object.
	 */
	NuevoMatchWorker(uint32_t worker_index, NuevoMatchConfig& configuration) :
		_listeners(), _worker_idx(worker_index),
		_isets(), _remainder(nullptr),
		_configuration(&configuration),
		_publish_results_time(0) {}

	virtual ~NuevoMatchWorker() {
		// This deletes also all iSets and the remainder classifier, if exists
		for (auto iset :_isets) {
			delete iset;
		}
		delete _remainder;
	}

	/**
	 * @brief Classify a batch of packets
	 * @param batch_id Unique identifier of the batch
	 * @param packets The batch packets
	 * @returns True in case the classification was consumed
	 */
	virtual bool classify(uint32_t batch_id, PacketBatch<N>& packets) = 0;

	/**
	 * @brief Add a new subset to this.
	 *        The subset memory will be deleted when this is destroyed.
	 */
	void add_subset(NuevoMatchSubset<N>& subset) {
		// What is the dynamic type the subset is holding?
		typename NuevoMatchSubset<N>::dynamic_type_t type = subset.get_type();
		// In case of an iSet, try to static-cast the subset to iset and add it
		if (type == NuevoMatchSubset<N>::dynamic_type_t::ISET) {
			IntervalSet<N>* iset = static_cast<IntervalSet<N>*>(&subset);
			if (iset == nullptr) {
				throw error("Cannot convert subset to its dynamic type iSet");
			}
			this->_isets.push_back(iset);
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

	/**
	 * @brief Adds listener to results of this
	 */
	void add_listener(NuevoMatchWorkerListener<N>& listener) {
		_listeners.push_back(&listener);
	}

	/**
	 * @brief Returns the number of subsets in this
	 */
	uint32_t count() const {
		uint32_t count = _isets.size();
		if (_remainder != nullptr) ++count;
		return count;
	}

	/**
	 * @brief Returns the number of rules held by all subsets in this
	 */
	uint32_t size() const {
		uint32_t output = 0;
		for (auto iset : _isets) {
			output += iset->size();
		}
		if (_remainder != nullptr) output += _remainder->size();
		return output;
	}

	/**
	 * @brief Returns a string representation of this
	 */
	virtual std::string to_string() const {
		std::stringstream ss;
		ss << "<";
		if (_remainder != nullptr) ss << _remainder->to_string();
		for (uint32_t i =0; i<_isets.size(); ++i) {
			ss << ", ";
			ss << _isets[i]->to_string();
		}
		ss << ">";
		return ss.str();
	}

	/**
	 * @brief Returns the time spent in publish new results (in usec).
	 */
	double get_publish_time() const {
		return this->_publish_results_time;
	}
};

/**
 * @brief A NuevoMatch worker than runs on the same thread as the dispatcher thread
 * @tparam N The number of packets in each batch
 */
template <uint32_t N>
class NuevoMatchWorkerSerial : NuevoMatchWorker<N> {
protected:

	struct timespec _start_time, _end_time;
	using Job = typename NuevoMatchWorker<N>::Job;

public:

	/**
	 * @brief Initialize new serial worker
	 * @param worker_idx A unique index for the worker
	 * @param configuration A reference to a NuevoMatch configuration object.
	 */
	NuevoMatchWorkerSerial(uint32_t worker_idx, NuevoMatchConfig& configuration)
		: NuevoMatchWorker<N>(worker_idx, configuration) {};

	virtual ~NuevoMatchWorkerSerial() {}

	using NuevoMatchWorker<N>::add_listener;
	using NuevoMatchWorker<N>::add_subset;
	using NuevoMatchWorker<N>::get_publish_time;

	/**
	 * @brief Starts the performance measurement of this
	 */
	void start_performance_measurements() {
		clock_gettime(CLOCK_MONOTONIC, &_start_time);
		this->_publish_results_time = 0;
	}

	/**
	 * @brief Stops the performance measurement of this
	 */
	void stop_performance_measurements(){
		clock_gettime(CLOCK_MONOTONIC, &_end_time);
	}

	/**
	 * @brief Returns the work time in micro seconds
	 */
	double get_work_time() const {
		return (_end_time.tv_sec - _start_time.tv_sec) * 1e6 +
				(double)(_end_time.tv_nsec - _start_time.tv_nsec) / 1e3;
	}

	/**
	 * @brief Classify a batch of packets
	 * @param batch_id Unique identifier of the batch
	 * @param packets The batch packets
	 * @returns True in case the classification was consumed
	 */
	virtual bool classify(uint32_t batch_id, PacketBatch<N>& packets) {
		// Classify Packets
		Job job = {packets, batch_id};
		NuevoMatchWorker<N>::work(job, this);
		return true;
	}
};


/**
 * @brief A NuevoMatch worker than runs on a different thread than the dispatcher.
 * @tparam N The number of packets in each batch
 */
template <uint32_t N>
class NuevoMatchWorkerParallel : NuevoMatchWorker<N> {
protected:

	using Job = typename NuevoMatchWorker<N>::Job;
	PipelineThread<Job>* _worker;

public:

	/**
	 * @brief Initialize new serial worker
	 * @param worker_idx A unique index for the worker
	 * @param configuration A reference to a NuevoMatch configuration object.
	 * @param core_idx The index of the CPU core to run on
	 */
	NuevoMatchWorkerParallel(uint32_t worker_idx, NuevoMatchConfig& configuration, uint32_t core_idx)
		: NuevoMatchWorker<N>(worker_idx, configuration)
	{
		if (configuration.queue_size % 2 != 0) {
			throw std::runtime_error("Queue size should be a power of two");
		}
		// Initialize the worker
		_worker = new PipelineThread<Job>(
				configuration.queue_size, core_idx,
				NuevoMatchWorker<N>::work, this);
	}

	virtual ~NuevoMatchWorkerParallel() {
		delete _worker;
	}

	using NuevoMatchWorker<N>::add_listener;
	using NuevoMatchWorker<N>::add_subset;
	using NuevoMatchWorker<N>::get_publish_time;

	/**
	 * @brief Classify a batch of packets
	 * @param batch_id Unique identifier of the batch
	 * @param packets The batch packets
	 * @returns True in case the worker consumed the job
	 */
	virtual bool classify(uint32_t batch_id, PacketBatch<N>& packets) {
		return _worker->produce({packets, batch_id});
	}

	/**
	 * @brief Starts the performance measurement of this
	 */
	void start_performance_measurements() {
		_worker->start_performance_measurements();
		this->_publish_results_time = 0;
	}

	/**
	 * @brief Stops the performance measurement of this
	 */
	void stop_performance_measurements(){
		_worker->stop_performance_measurements();
	}

	/**
	 * @brief Returns the throughput of this (requests per us)
	 */
	double get_throughput() const {
		return _worker->get_throughput();
	}

	/**
	 * @brief Returns the utilization percent
	 */
	double get_utilization() const {
		return _worker->get_utilization();
	}

	/**
	 * @brief Returns the ratio of declined requests (requests per us).
	 */
	double get_backpressure() const {
		return _worker->get_backpressure();
	}

	/**
	 * @brief Returns the average work time per request (in us).
	 */
	double get_average_work_time() const {
		return _worker->get_average_work_time();
	}
};
