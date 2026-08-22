

#pragma once
#ifndef TSCIRCULARQUEUE_H
#define TSCIRCULARQUEUE_H

#include "common.h"
#include "protocol.h"

namespace Buffer
{

    template <std::size_t Size, std::size_t Max_Pkt_Size>
    class CircularQueue
    {
    public:
        CircularQueue(std::condition_variable &cond_var,
                      std::counting_semaphore<10> &sem_ref)
            : head(0),
              tail(0),
              count(0),
              tempHead(0),
              signal(cond_var),
              sema(sem_ref),
              buffer(std::make_unique<uint8_t[]>(Size))
        {
        }

        //  void enqueue(std::queue<uint8_t>* data, uint16_t length) {
        //      if (is_full()) {
        //          throw std::overflow_error("Queue is full");
        //      }
        //      // TICK: Need to test
        //      // Check for null pointer (optional but good practice)
        //      if (data == nullptr) {
        //          return;
        //      }
        //      // Lock the buffer to add a packet
        // std::scoped_lock lock(muxQueue);
        //      // Inserting additional internal packet
        //      PROTOCOL::internal_hdr int_hdr(length);
        //
        //      std::memcpy(&buffer[tail], &int_hdr, PROTOCOL::internal_hdr_size);
        //
        //      // Loop till the queue is empty and place it in the buffer
        //      for (size_t i {PROTOCOL::internal_hdr_size}; !data->empty(); i++) {
        //          buffer[tail + i] = data->front();
        //          data->pop();
        //      }
        //      // Change the tail index after the packet has shifted entirely
        //      tail = (tail + Max_Pkt_Size) % Size;
        //      // Increased the packet count
        //      ++count;
        //      //spdlog::info("Increment Count: {}", +count);
        //      // Notify waiting threads
        //      cvBlocking.notify_one();
        //      spdlog::info("ADDED");
        //  }

        //  // If we know
        //  void enqueue(std::queue<uint8_t> *data, uint16_t length, uint8_t output_port) {
        //      if (is_full()) {
        //          throw std::overflow_error("Queue is full");
        //      }
        //      // TICK: Need to test
        //      // Check for null pointer (optional but good practice)
        //      if (data == nullptr) {
        //          return;
        //      }
        //      // Lock the buffer to add a packet
        // std::scoped_lock lock(muxQueue);
        //
        //      // Inserting additional internal packet
        //      PROTOCOL::internal_hdr int_hdr(length, output_port);
        //
        //      std::memcpy(&buffer[tail], &int_hdr, PROTOCOL::ethernet_hdr_size);
        //
        //      // Loop till the queue is empty and place it in the buffer
        //      for (size_t i {PROTOCOL::ethernet_hdr_size}; !data->empty(); i++) {
        //          buffer[tail + i] = data->front();
        //          data->pop();
        //      }
        //      // Change the tail index after the packet has shifted entirely
        //      tail = (tail + Max_Pkt_Size) % Size;
        //      // Increased the packet count
        //      ++count;
        //      //spdlog::info("Increment Count: {}", +count);
        //      spdlog::info("ADDED");
        //      // std::cout<<"ADDED";
        //      cvBlocking.notify_one(); // Notify waiting threads
        //  }

        void enqueue(std::deque<uint8_t> *data)
        {
            if (is_full())
            {
                throw std::overflow_error("Queue is full");
            }

            // Check for null pointer
            if (data == nullptr)
            {
                std::cout << "NULL POINTER\n";
                return;
            }
            // Lock the buffer to add a packet
            std::scoped_lock lock(muxQueue);
            // std::cout<<"Enqueue: "<<data->size()<<std::endl;

            // Loop till the deque is empty and place it in the buffer
            for (size_t i{}; !data->empty(); i++)
            {
                // std::cout<<+data->front()<<" ";

                buffer[tail + i] = data->front();
                data->pop_front();
            }

            // Change the tail index after the packet has shifted entirely
            tail = (tail + Max_Pkt_Size) % Size;
            // Increased the packet count
            ++count;

            // spdlog::info("Increment Count: {}", +count);
            sema.release();

            // Notify waiting scheduler
            signal.notify_one();
            spdlog::info("ADDED");
        }

        /*void enqueue(std::deque<uint8_t>* data, uint8_t output_port) {
            if (is_full()) {
                throw std::overflow_error("Queue is full");
            }

            // Check for null pointer
            if (data == nullptr) {
                return;
            }
            // Lock the buffer to add a packet
            std::scoped_lock lock(muxQueue);
            // std::cout<<"Enqueue: "<<data->size()<<std::endl;

            // Inserting additional internal packet
            PROTOCOL::internal_hdr internal_hdr(static_cast<uint16_t>(data->size()),output_port);
            // std::cout<<PROTOCOL::internal_hdr_size<<std::endl;

            std::list<uint8_t> temp;
            internal_hdr.serialize(temp);
            // internal_hdr.display();

            data->insert(data->begin(),temp.begin(),temp.end());

            // Loop till the deque is empty and place it in the buffer
            for (size_t i {}; !data->empty(); i++) {
                // std::cout<<+data->front()<<" ";

                buffer[tail + i] = data->front();
                data->pop_front();
            }
            // Change the tail index after the packet has shifted entirely
            tail = (tail + Max_Pkt_Size) % Size;
            // Increased the packet count
            ++count;

            //spdlog::info("Increment Count: {}", +count);
            sema.release();

            // Notify waiting scheduler
            signal.notify_one();

            spdlog::info("ADDED");
        }*/

        void enqueue(std::vector<uint8_t> *data)
        {
            if (is_full())
            {
                throw std::overflow_error("Queue is full");
            }

            // Check for null pointer
            if (data == nullptr)
            {
                return;
            }
            // Lock the buffer to add a packet
            std::scoped_lock lock(muxQueue);
            // std::cout<<"Enqueue: "<<data->size()<<std::endl;

            // Loop till end of vector and place it in the buffer
            for (size_t i{}; i < data->size(); i++)
            {
                // std::cout<<+data->at(i)<<" ";
                buffer[tail + i] = data->at(i);
            }
            // Change the tail index after the packet has shifted entirely
            tail = (tail + Max_Pkt_Size) % Size;
            // Increased the packet count
            ++count;
            // spdlog::info("Increment Count: {}", +count);

            // Increased the counting semaphore
            sema.release();

            // Notify waiting scheduler
            signal.notify_one();
            spdlog::info("ADDED");
        }

        /*void enqueue(std::vector<uint8_t>* data, uint8_t output_port) {
            if (is_full()) {
                throw std::overflow_error("Queue is full");
            }
            // TICK: Need to test
            // Check for null pointer (optional but good practice)
            if (data == nullptr) {
                return;
            }
            // Lock the buffer to add a packet
            std::scoped_lock lock(muxQueue);

            // Inserting additional internal packet
            PROTOCOL::internal_hdr internal_hdr(static_cast<uint16_t>(data->size()), output_port);

            std::list<uint8_t> temp;
            internal_hdr.serialize(temp);
            // internal_hdr.display();

            data->insert(data->begin(),temp.begin(),temp.end());

            for (size_t i {}; i < data->size(); i++) {
                // std::cout<<+data->at(i)<<" ";

                buffer[tail + i] = data->at(i);
            }

            // Change the tail index after the packet has shifted entirely
            tail = (tail + Max_Pkt_Size) % Size;
            // Increased the packet count
            ++count;
            //spdlog::info("Increment Count: {}", +count);

            // Increased the counting semaphore
            sema.release();

            // Notify waiting scheduler
            signal.notify_one();

            spdlog::info("ADDED");

        }*/

        void enqueueWithoutIHdr(std::deque<uint8_t> *data)
        {
            if (is_full())
            {
                throw std::overflow_error("Queue is full");
            }

            // Check for null pointer
            if (data == nullptr)
            {
                return;
            }
            // Lock the buffer to add a packet
            std::scoped_lock lock(muxQueue);
            // std::cout<<"Enqueue: "<<data->size()<<std::endl;

            // Inserting additional internal packet
            PROTOCOL::internal_hdr internal_hdr(static_cast<uint16_t>(data->size()));
            // std::cout<<PROTOCOL::internal_hdr_size<<std::endl;

            std::list<uint8_t> temp;
            internal_hdr.serialize(temp);
            // internal_hdr.display();

            data->insert(data->begin(), temp.begin(), temp.end());

            // Loop till the deque is empty and place it in the buffer
            for (size_t i{}; !data->empty(); i++)
            {
                // std::cout<<+data->front()<<" ";

                buffer[tail + i] = data->front();
                data->pop_front();
            }
            // Change the tail index after the packet has shifted entirely
            tail = (tail + Max_Pkt_Size) % Size;
            // Increased the packet count
            ++count;

            // spdlog::info("Increment Count: {}", +count);
            sema.release();

            // Notify waiting scheduler
            signal.notify_one();
            spdlog::info("ADDED");
        }

        void drop_packet()
        {
            if (is_empty())
            {
                throw std::underflow_error("Queue is empty");
            }
            std::scoped_lock lock(muxQueue);
            head = (head + Max_Pkt_Size) % Size;
            // std::cout<<"\n DROPPED"<<std::endl;
            --count;
            // spdlog::critical("Decrement Count: {}", +count);
        }

        void dequeue(std::vector<uint8_t> *packet)
        {
            if (is_empty())
            {
                throw std::underflow_error("Queue is empty");
            }
            uint16_t length = front_pkt_length();

            std::scoped_lock lock(muxQueue);

            for (uint16_t i{}; i < length; i++)
            {
                // std::cout<<+buffer[head + i]<<" ";
                packet->push_back(buffer[head + i]);
            }

            head = (head + Max_Pkt_Size) % Size;
            --count;
            // spdlog::critical("Decrement Count: {}", +count);
        }

        // Get the front packet length
        uint32_t front_pkt_length() const
        {
            if (is_empty())
            {
                throw std::underflow_error("Queue is empty");
            }
            uint16_t size = static_cast<uint16_t>(buffer[head] << 8 | buffer[head + 1]);
            return size;
        }

        // Insert a copy of front packet in RAM
        void insert_copy_in_ram(std::vector<uint8_t> &ram, std::condition_variable &cond_var_ram) const
        {
            if (is_empty())
            {
                throw std::underflow_error("Queue is empty");
            }
            uint32_t size = front_pkt_length();
            std::scoped_lock lock(muxQueue);
            ram.resize(size);
            std::memcpy(static_cast<void *>(ram.data()),
                        buffer.get() + head,
                        (size) * sizeof(uint8_t));
            // Raising an interrupt that a new packet has been copied to RAM for processing
            cond_var_ram.notify_one();
            spdlog::info("Inserted in Ram");
        }

        /*
            void insert_copy_in_ram(std::deque<uint8_t> &ram, std::condition_variable &cond_var_ram) {
                uint32_t size = front_pkt_length() + 3;
                // ram.resize(size);
                // std::cout<<"SIZE: "<<+size<<" ";

                tempHead = head;
                // while(size>=0){
                    // ram.push_back(buffer[tempHead++]);
                    // size--;
                // }
                std::memcpy(static_cast<void*>(&ram[0]),
                            buffer.get() + head,
                            size * sizeof(uint8_t));
                // Raising an interrupt that a new packet has been copied to RAM for processing
                for(auto el:ram)
                    std::cout<<+el<<" ";

                cond_var_ram.notify_one();
                std::cout << "Inserted in RAM" << std::endl;
            }
        */

        // Just check if number of packets in buffer is zero
        bool is_empty() const
        {
            std::scoped_lock lock(muxQueue);
            // Use std::atomic<size_t> for thread-safe atomic access to count
            std::atomic<size_t> current_count(count);
            // Acquire the latest value of count using memory_order_acquire
            return current_count.load(std::memory_order_acquire) == 0;
        }

        // Since the number of packets allowed is maximum as the number of
        // segments we can get just if count of packet equal to number of segmetns
        bool is_full() const
        {
            std::scoped_lock lock(muxQueue);
            // Use std::atomic<size_t> for thread-safe atomic access to count
            std::atomic<size_t> current_count(count);
            // Acquire the latest value of count using memory_order_acquire
            // spdlog::error("Count: {}", +(current_count.load(std::memory_order_acquire) == Size / Max_Pkt_Size));
            // spdlog::error("max: {} {}", +current_count.load(std::memory_order_acquire), +(Size/Max_Pkt_Size));
            return (current_count.load(std::memory_order_acquire) == (Size / Max_Pkt_Size));
        }

        std::size_t number_of_packets() const
        {
            std::scoped_lock lock(muxQueue);
            return count;
        }

        ~CircularQueue() {}

    private:
        // std::array<uint8_t, Size>* buffer = new array<uint8_t,Size>();
        std::unique_ptr<uint8_t[]> buffer;
        size_t head;
        size_t tail;
        size_t count;
        size_t tempHead;
        std::counting_semaphore<10> &sema;
        std::condition_variable &signal;

    protected:
        mutable std::mutex muxQueue;
        std::condition_variable cvBlocking;
        mutable std::mutex muxBlocking;
    };

} // END NAMESPACE BUFFER

#endif
