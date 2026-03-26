use std::str::FromStr;
use jiff::{Timestamp, Zoned};

fn main() {
    let input = "2025-02-18T08:25:15+00:00";
    
    // Test jiff parsing directly
    let timestamp = Timestamp::from_str(input).unwrap();
    println!("Timestamp parsed: {}", timestamp);
    
    let formatted = format!("{}", timestamp);
    println!("Timestamp formatted: {}", formatted);
    
    if formatted.ends_with("+00:00") {
        println!("Would convert to: {}Z", &formatted[..formatted.len()-6]);
    }
}