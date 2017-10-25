#ifndef QUEUE_H
#define QUEUE_H

#include <vector>
#include <mutex>
#include <condition_variable>
#include <utility>
#include <atomic>
#include "packet.h"

template <typename T>
class MessageQueue
{
public:

    using Queue_t = std::vector<T>;

    MessageQueue() : m_flag_exit(false) {}
    ~MessageQueue()
    {
        m_queue.clear();
    }

    void Enqueue(T&& message)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_queue.push_back(std::forward<T>(message));
        }
        m_cond_var.notify_one();
    }

    Queue_t DequeueAll()
    {
        std::unique_lock<std::mutex> ulm(m_mutex);
        m_cond_var.wait(ulm, [&](){ return (!m_queue.empty() || m_flag_exit);});
        Queue_t q = std::move(m_queue);
        return q;
    }

    void NotifyExit()
    {
        m_flag_exit = true;
        m_cond_var.notify_one();
    }

    MessageQueue(const MessageQueue&) = delete;
    MessageQueue& operator=(const MessageQueue&) = delete;
    MessageQueue(MessageQueue&&) = delete;
    MessageQueue& operator=(MessageQueue&&) = delete;

private:

    Queue_t                     m_queue;
    std::mutex                  m_mutex;
    std::condition_variable     m_cond_var;
    std::atomic_bool            m_flag_exit;
};

#endif // QUEUE_H
