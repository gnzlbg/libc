s! {
    pub struct pthread_mutexattr_t {
        #[cfg(target_arch = "x86_64")]
        pub __align: [::c_int; 0],
        #[cfg(not(target_arch = "x86_64"))]
        pub __align: [::c_long; 0],
        pub size: [u8; ::__SIZEOF_PTHREAD_MUTEXATTR_T],
    }

    pub struct pthread_rwlockattr_t {
        pub __align: [::c_long; 0],
        pub size: [u8; ::__SIZEOF_PTHREAD_RWLOCKATTR_T],
    }

    pub struct pthread_condattr_t {
        pub __align: [::c_int; 0],
        pub size: [u8; ::__SIZEOF_PTHREAD_CONDATTR_T],
    }
}

s_no_extra_traits! {
    #[allow(missing_debug_implementations)]
    pub struct pthread_mutex_t {
        #[cfg(any(target_arch = "arm",
                  all(target_arch = "x86_64",
                      target_pointer_width = "32")))]
        pub __align: [::c_long; 0],
        #[cfg(not(any(target_arch = "arm",
                      all(target_arch = "x86_64",
                          target_pointer_width = "32"))))]
        pub __align: [::c_longlong; 0],
        pub size: [u8; ::__SIZEOF_PTHREAD_MUTEX_T],
    }

    #[allow(missing_debug_implementations)]
    pub struct pthread_rwlock_t {
        pub __align: [::c_long; 0],
        pub __align: [::c_longlong; 0],
        pub size: [u8; ::__SIZEOF_PTHREAD_RWLOCK_T],
    }

    #[allow(missing_debug_implementations)]
    pub struct pthread_cond_t {
        pub __align: [*const ::c_void; 0],
        #[cfg(not(target_env = "musl"))]
        pub __align: [::c_longlong; 0],
        pub size: [u8; ::__SIZEOF_PTHREAD_COND_T],
    }
}
