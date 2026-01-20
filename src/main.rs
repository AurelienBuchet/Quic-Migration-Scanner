mod common;
mod args;
mod quiche_client;
mod tester;
#[macro_use]
extern crate log;
use crate::tester::*;
use std::{fs::File, io::{BufRead, BufReader, Write}, net::IpAddr, thread};
use args::Parseable;
use common::Target;
use crossbeam_channel::bounded;

fn main() {
    env_logger::init();

    let docopt = docopt::Docopt::new(args::USAGE).unwrap();
    let args = args::Args::with_docopt(&docopt);

    let filename = args.file_path;
    let file = File::open(filename).unwrap();
    let reader = BufReader::new(file);

    let n_threads = args.n_threads;

    let (send_url, recv_url) = bounded(n_threads+2);
    let (send_result, recv_result) = bounded(n_threads+2);

    let mut thread_handles = Vec::new();
    for _ in 0..n_threads {
        let (quic_thread_recv, quic_thread_send) = (recv_url.clone(), send_result.clone());
        let handle = thread::spawn(move || {
            loop {
                let target = match quic_thread_recv.recv() {
                    Ok(val) => val,
                    Err(_) => break
                };
                let result = test_migration(&target, args.primary_ip, args.migration_ip, args.wait_headers, args.migration_type, args.fast);
                quic_thread_send.send(result).unwrap();
            }
        });
        thread_handles.push(handle);
    }

    let mut out_file = File::create(args.out_file).unwrap();
    out_file.write(b"[").expect("Failed to write");
    let write_handle = thread::spawn(move ||{
        let mut i: i32 = 0;
        let mut first = true;
        loop {
            if i % 1000 == 0{
                info!("probed {i} domains");
            }
            let test_quic_migration = match recv_result.recv(){
                Ok(val) => {
                    debug!("received a result {:?}", val.url);
                    val
                },
                Err(_) => {
                    out_file.write("\n]".as_bytes()).expect("Failed to write line");
                    break
                }
            };
            let res = if first {
                first = false;
                format!("\n{}",test_quic_migration)
            } else {
                format!(",\n{}", test_quic_migration)
            };
            out_file.write(res.as_bytes()).expect("Failed to write line");
            debug!("Test result error : {:?}", test_quic_migration.error);
            i+=1;
        }
    });

    let mut lines = reader.lines();
    let _skip_header = lines.next();

    loop {
        let line = match lines.next() {
            Some(val) => val,
            None => break
        };
        let line = line.expect("Failed to read file");
        let target = match create_target(&line) {
            Some(val) => val,
            None => continue
        };
        send_url.send(target).unwrap();
    }

    info!("Done parsing");

    drop(send_url);
    for handle in thread_handles{
        match handle.join() {
            Ok(_) => {},
            Err(_) => {}
        }
    }
    info!("Done processing");
    drop(send_result);

    write_handle.join().unwrap();
}

fn create_target(line: &str) -> Option<Target>{
    let parts = line.split(",").collect::<Vec<&str>>();
    let ip:IpAddr = match parts[0].parse() {
        Ok(val) => val,
        Err(e) => {
            error!("Error parsing IP from line {}: {:?}", line, e);
            return None;
        }
    };
    let domain = create_url(parts[1].trim(), parts[0].trim());

    Some(Target::new(ip, domain))
}

fn create_url(domain: &str, ip: &str) -> String{
    if domain == ""{
        if ip.contains(":"){
            return format!("https://[{}]",ip).trim().replace('"', "");
        }
        return format!("https://{:?}",ip).trim().replace('"', "");
    }
    format!("https://{:?}",domain).trim().replace('"', "")
}