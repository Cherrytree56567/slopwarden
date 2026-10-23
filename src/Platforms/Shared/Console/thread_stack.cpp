#include <pthread.h>

/*
 * The consoles' pthread layers give threads a tiny stack unless told otherwise (8 KB on the Wii),
 * and std::thread/std::jthread never say: far too small for the core's workers, TLS handshakes or key derivation, which
 * overflow it and crash. The link wraps pthread_create (-Wl,--wrap=pthread_create) so threads
 * created without attributes get a real stack.
 */
namespace {
    constexpr size_t c_thread_stack = 256 * 1024;
}

extern "C" {
int __real_pthread_create(pthread_t* thread, const pthread_attr_t* attr, void* (*start)(void*), void* arg);

int __wrap_pthread_create(pthread_t* thread, const pthread_attr_t* attr, void* (*start)(void*), void* arg) {
    if (attr) {
        return __real_pthread_create(thread, attr, start, arg);
    }
    pthread_attr_t sized;
    pthread_attr_init(&sized);
    pthread_attr_setstacksize(&sized, c_thread_stack);
    int result = __real_pthread_create(thread, &sized, start, arg);
    pthread_attr_destroy(&sized);
    return result;
}
}
