

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            return Err(core::convert::From::from($e));
        }
    };
}
