/// A macro for defining #[cfg] if-else statements.
///
/// This is similar to the `if/elif` C preprocessor macro by allowing definition
/// of a cascade of `#[cfg]` cases, emitting the implementation which matches
/// first.
///
/// This allows you to conveniently provide a long list #[cfg]'d blocks of code
/// without having to rewrite each clause multiple times.
macro_rules! cfg_if {
    // match if/else chains with a final `else`
    ($(
        if #[cfg($($meta:meta),*)] { $($it:item)* }
    ) else * else {
        $($it2:item)*
    }) => {
        cfg_if! {
            @__items
            () ;
            $( ( ($($meta),*) ($($it)*) ), )*
            ( () ($($it2)*) ),
        }
    };

    // match if/else chains lacking a final `else`
    (
        if #[cfg($($i_met:meta),*)] { $($i_it:item)* }
        $(
            else if #[cfg($($e_met:meta),*)] { $($e_it:item)* }
        )*
    ) => {
        cfg_if! {
            @__items
            () ;
            ( ($($i_met),*) ($($i_it)*) ),
            $( ( ($($e_met),*) ($($e_it)*) ), )*
            ( () () ),
        }
    };

    // Internal and recursive macro to emit all the items
    //
    // Collects all the negated cfgs in a list at the beginning and after the
    // semicolon is all the remaining items
    (@__items ($($not:meta,)*) ; ) => {};
    (@__items ($($not:meta,)*) ; ( ($($m:meta),*) ($($it:item)*) ), $($rest:tt)*) => {
        // Emit all items within one block, applying an approprate #[cfg]. The
        // #[cfg] will require all `$m` matchers specified and must also negate
        // all previous matchers.
        cfg_if! { @__apply cfg(all($($m,)* not(any($($not),*)))), $($it)* }

        // Recurse to emit all other items in `$rest`, and when we do so add all
        // our `$m` matchers to the list of `$not` matchers as future emissions
        // will have to negate everything we just matched as well.
        cfg_if! { @__items ($($not,)* $($m,)*) ; $($rest)* }
    };

    // Internal macro to Apply a cfg attribute to a list of items
    (@__apply $m:meta, $($it:item)*) => {
        $(#[$m] $it)*
    };
}

macro_rules! s {
    ($($(#[$attr:meta])* pub $t:ident $i:ident { $($field:tt)* })*) => ($(
        s!(it: $(#[$attr])* pub $t $i { $($field)* });
    )*);
    (it: $(#[$attr:meta])* pub union $i:ident { $($field:tt)* }) => (
        compile_error!("unions cannot derive extra traits, use s_no_extra_traits instead");
    );
    (it: $(#[$attr:meta])* pub struct $i:ident { $($field:tt)* }) => (
        __item! {
            #[repr(C)]
            #[cfg_attr(feature = "extra_traits", derive(Debug, Eq, Hash, PartialEq))]
            $(#[$attr])*
            pub struct $i { $($field)* }
        }
        impl ::dox::Copy for $i {}
        impl ::dox::Clone for $i {
            fn clone(&self) -> $i { *self }
        }
    );
}

macro_rules! s_no_extra_traits {
    ($($(#[$attr:meta])* pub $t:ident $i:ident { $($field:tt)* })*) => ($(
        s_no_extra_traits!(it: $(#[$attr])* pub $t $i { $($field)* });
    )*);
    (it: $(#[$attr:meta])* pub union $i:ident { $($field:tt)* }) => (
        cfg_if! {
            if #[cfg(libc_union)] {
                __item! {
                    #[repr(C)]
                    $(#[$attr])*
                    pub union $i { $($field)* }
                }

                impl ::dox::Copy for $i {}
                impl ::dox::Clone for $i {
                    fn clone(&self) -> $i { *self }
                }
            }
        }
    );
    (it: $(#[$attr:meta])* pub struct $i:ident { $($field:tt)* }) => (
        __item! {
            #[repr(C)]
            $(#[$attr])*
            pub struct $i { $($field)* }
        }
        impl ::dox::Copy for $i {}
        impl ::dox::Clone for $i {
            fn clone(&self) -> $i { *self }
        }
    );
}

#[allow(unused_macros)]
macro_rules! f {
    ($(pub fn $i:ident($($arg:ident: $argty:ty),*) -> $ret:ty {
        $($body:stmt);*
    })*) => ($(
        #[inline]
        #[cfg(not(cross_platform_docs))]
        pub unsafe extern fn $i($($arg: $argty),*) -> $ret {
            $($body);*
        }

        #[cfg(cross_platform_docs)]
        #[allow(dead_code)]
        pub unsafe extern fn $i($($arg: $argty),*) -> $ret {
            loop {}
        }
    )*)
}

macro_rules! __item {
    ($i:item) => {
        $i
    };
}

#[allow(unused_macros)]
macro_rules! align_const {
    ($($(#[$attr:meta])* pub const $name:ident : $t1:ty = $t2:ident { $($field:tt)* };)*) => ($(
        #[cfg(libc_align)]
        $(#[$attr])*
        pub const $name : $t1 = $t2 {
            $($field)*
        };
        #[cfg(not(libc_align))]
        $(#[$attr])*
        pub const $name : $t1 = $t2 {
            $($field)*
            __align: [],
        };
    )*)
}
