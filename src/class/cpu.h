// #pragma once

// // #include <iostream>
// // #include <thread>
// // #include <functional>
// // #include <memory>

// namespace CPU
// {

// class WorkerThread {
// public:
//     // Constructor
//     WorkerThread() : thread_(nullptr) {}

//     // Destructor
//     ~WorkerThread() {
//         if (thread_ && thread_->joinable()) {
//             thread_->join();
//         }
//     }

//     // Delete copy constructor and copy assignment to avoid issues
//     WorkerThread(const WorkerThread&) = delete;
//     WorkerThread& operator=(const WorkerThread&) = delete;

//     // Move constructor and move assignment
//     WorkerThread(WorkerThread&& other) noexcept {
//         thread_ = std::move(other.thread_);
//     }

//     WorkerThread& operator=(WorkerThread&& other) noexcept {
//         if (this != &other) {
//             if (thread_ && thread_->joinable()) {
//                 thread_->join();
//             }
//             thread_ = std::move(other.thread_);
//         }
//         return *this;
//     }

//     // Start the thread with a function
//     template<typename Function, typename... Args>
//     auto start(Function&& func, Args&&... args) -> std::future<decltype(std::declval<Function>()(std::declval<Args>()...))> {
//         using ReturnType = decltype(func(std::forward<Args>(args)...));

//         if (thread_ && thread_->joinable()) {
//             thread_->join();
//         }

//         auto promise_ptr = std::make_shared<std::promise<ReturnType>>();

//         thread_ = std::make_unique<std::thread>(
//             [promise_ptr, func = std::forward<Function>(func), ...args = std::forward<Args>(args)]() mutable {
//                 try {
//                     promise_ptr->set_value(func(std::forward<Args>(args)...));
//                 } catch (...) {
//                     promise_ptr->set_exception(std::current_exception());
//                 }
//             });

//         return promise_ptr->get_future();
//     }


// private:
//     std::unique_ptr<std::thread> thread_;
// };

// } // END NAMESPACE CPU

#pragma once

// #include <iostream>
// #include <thread>
// #include <functional>
// #include <memory>
// #include <future>

// namespace CPU {
//class WorkerThread {
//public:
//    // Constructor
//    WorkerThread(std::atomic<bool>& i_interrupt,std::atomic<bool>& o_interrupt,std::atomic<bool>& r_interrupt): input_interrupt(i_interrupt),output_interrupt(o_interrupt),ram_interrupt(r_interrupt) {};
//    // explicit WorkerThread(StopFlag& stop_flag) : stop_flag_(stop_flag) {}
//    // Destructor
//    ~WorkerThread() = default;
//
//    // Delete copy constructor and copy assignment to avoid issues
//    WorkerThread(const WorkerThread&) = delete;
//    WorkerThread& operator=(const WorkerThread&) = delete;
//
//    // Move constructor and move assignment
//    WorkerThread(WorkerThread&& other) noexcept = default;
//    WorkerThread& operator=(WorkerThread&& other) noexcept = default;
//
//    // Start the thread with a function
//    template<typename Function, typename... Args>
//    auto start(Function&& func, Args&&... args) -> std::future<decltype(std::declval<Function>()(std::declval<Args>()...))> {
//        using ReturnType = decltype(func(std::forward<Args>(args)...));
//
//        auto promise_ptr = std::make_shared<std::promise<ReturnType>>();
//        auto future = promise_ptr->get_future();
//
//        std::thread([promise_ptr, func = std::forward<Function>(func), ...args = std::forward<Args>(args)]() mutable {
//            try {
//                promise_ptr->set_value(func(std::forward<Args>(args)...));
//            } catch (...) {
//                promise_ptr->set_exception(std::current_exception());
//            }
//        }).detach(); // Detach the thread immediately
//
//        return future;
//    }
//
//    //  // Start the thread with a function
//    // template<typename Function, typename... Args>
//    // auto start(Function&& func, Args&&... args) 
//    // -> std::future<void> {
//    //     auto promise_ptr = std::make_shared<std::promise<void>>();
//    //     auto future = promise_ptr->get_future();
//
//    //     worker_ = std::thread([promise_ptr, this, func = std::forward<Function>(func), ...args = std::forward<Args>(args)]() mutable {
//    //         try {
//    //             while (!stop_flag_) {
//    //                 func(std::forward<Args>(args)...);
//    //                 // Add a short sleep to prevent busy-waiting
//    //                 std::this_thread::sleep_for(std::chrono::milliseconds(10));
//    //             }
//    //             promise_ptr->set_value();
//    //         } catch (...) {
//    //             promise_ptr->set_exception(std::current_exception());
//    //         }
//    //     });
//
//    //     return future;
//    // }
//
//private:
//    // No need for a thread_ member since threads are detached
//    std::atomic<bool> &input_interrupt;
//    std::atomic<bool> &output_interrupt;
//    std::atomic<bool> &ram_interrupt;
//    // std::thread worker_;/
//};

// } // END NAMESPACE CPU
