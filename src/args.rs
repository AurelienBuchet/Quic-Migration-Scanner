use std::{net::IpAddr, str::FromStr};

use crate::common::MigrationType;

pub trait Parseable {
    fn with_docopt(docopt: &docopt::Docopt) -> Self;
}

pub struct Args {
    pub file_path: String,
    pub n_threads: usize,
    pub out_file: String,
    pub wait_headers: bool,
    pub migration_type: MigrationType,
    pub migration_ip: Option<IpAddr>,
    pub primary_ip: Option<IpAddr>,
    pub fast: bool,
}

pub const USAGE: &str = "Usage:
  migration_checker [options] FILE
  migration_checker -h | --help

Options:
  --threads THREADS             Use the given number of thread [default: 100].
  -o --output FILE              Write the result to the given file [default: out.json].
  -w --wait-headers             Wait response header before migration.
  -m --migration-addr ADDRESS   Perform connection migration on the given address.
  -i --interface ADDRESS        Use the provide interface as primary address.
  -h --help                     Show this screen.
  -t --type TYPE                Change the type of migration checked [default: standard].
  -f --fast                     Shutdown the connection once headers are received.
";

impl Parseable for Args {
    fn with_docopt(docopt: &docopt::Docopt) -> Self {
        let args = docopt.parse().unwrap_or_else(|e| e.exit());
        let file_path = args.get_str("FILE").to_string();
        let out_file = match args.get_str("--output") {
            "" => "out.json".to_string(),
            file => file.to_string()
        };
        let n_threads = match args.get_str("--threads") {
            "" => 100,
            val => val.parse().expect("Invalid Number")
        };
        let migration_ip = match args.get_str("--migration-addr") {
            "" => None,
            val => Some(IpAddr::from_str(val).expect("Failed to parse IP"))
        };
        let primary_ip = match args.get_str("--interface") {
            "" => None,
            val => Some(IpAddr::from_str(val).expect("Failed to parse IP"))
        };
        let wait_headers = args.get_bool("--wait-headers");
        let migration_type = match args.get_str("--type") {
            "" => MigrationType::Standard,
            "standard" => MigrationType::Standard,
            "passive" => MigrationType::Passive,
            "reuseCID" => MigrationType::ReusedCID,
            _ => panic!("Unknown migration type. migrations supported: standard, passive, reuseCID")
        };
        let fast = args.get_bool("--fast");
        Args { 
            file_path,
            n_threads,
            out_file,
            wait_headers,
            migration_type,
            migration_ip,
            primary_ip,
            fast
        }
    }
}