use once_cell::sync::Lazy;
use regex::Regex;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct DnsLog {
    timestamp: String,
    client_address: String,
    protocol: String,
    qname: String,
    qtype: String,
    qclass: String,
    rcode: String,
    answer: String,
}

fn main() {
    // Get user input
    let args: Vec<String> = env::args().collect();
    let file_name = &args[1];

    match file_exists(file_name) {
        Ok(_file_path) => {}
        Err(err) => println!("Error: {}", err),
    }

    if let Ok(lines) = read_lines(file_name) {
        for line in lines {
            if let Ok(file_line) = line {
                if let Some(parsed_log) = parse_technitium_logline(&file_line) {
                    println!("{:?}", parsed_log);
                }
            }
        }
    }
}

fn parse_technitium_logline(line: &str) -> Option<DnsLog> {
    if let Some(captures) = LOGLINE_REGEX.captures(line) {
        Some(DnsLog {
            timestamp: captures["timestamp"].to_string(),
            client_address: captures["ip_address"].to_string(),
            protocol: captures["protocol"].to_string(),
            qname: captures["qname"].to_string(),
            qtype: captures["qtype"].to_string(),
            qclass: captures["qclass"].to_string(),
            rcode: captures["rcode"].to_string(),
            answer: captures["answer"].to_string(),
        })
    } else {
        None
    }
}

static LOGLINE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\[(?P<timestamp>[\d\s:-]+) UTC\] \[(?P<ip_address>[\d.:]+)\] \[(?P<protocol>\w+)\] QNAME: (?P<qname>[^;]+); QTYPE: (?P<qtype>\w+); QCLASS: (?P<qclass>\w+); RCODE: (?P<rcode>\w+); ANSWER: \[(?P<answer>[\d.,\s]+)\]"#).unwrap()
});

fn file_exists(file_path: &str) -> Result<PathBuf, Box<dyn Error>> {
    // Check if the file exists
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(format!("File not found: {}", file_path).into());
    };
    return Ok(path.to_path_buf());
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
