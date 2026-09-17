#![no_main]

use libfuzzer_sys::fuzz_target;
use merino::{AddrType, pretty_print_addr};

fuzz_target!(|data: &[u8]| {
    let _ = pretty_print_addr(&AddrType::V4, data);
    let _ = pretty_print_addr(&AddrType::V6, data);
    let _ = pretty_print_addr(&AddrType::Domain, data);
});
