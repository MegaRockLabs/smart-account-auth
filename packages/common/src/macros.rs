#[macro_export]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            return Err(core::convert::From::from($e));
        }
    };
}


#[macro_export]
macro_rules! mod_use {
    ($modname:ident) => {
        mod $modname;
        pub use $modname::*;
    };
}


#[macro_export]
macro_rules! cfg_mod_use {
    ($feature:literal, $modname:ident) => {
        #[cfg(feature = $feature)]
        mod $modname;
        #[cfg(feature = $feature)]
        pub use $modname::*;
    };
}


#[macro_export]
macro_rules! cfg_mod_pub {
    ($feature:literal, $modname:ident) => {
        #[cfg(feature = $feature)]
        pub mod $modname;
        #[cfg(not(feature = $feature))]
        mod $modname;
    };
}
