
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;
use std::{net::SocketAddr, str::FromStr};

use quiche::Stats;

#[derive(Debug)]
pub struct Target{
    pub domain: String,
    pub ip: IpAddr,
    pub port: u16,
}

impl Target{
    pub fn new(ip: IpAddr,domain: String) -> Target{
        Target{ 
            ip,
            domain,
            port: 443
        }
    }
}

#[derive(Debug)]
pub enum TestError{
    ResolutionError,
    ConnectionError,
    ReadError,
    SendError,
    HTTPError,
    MigrationError,
    TooManyRedirect,
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationStatus{
    Success,
    Migrated,
    Failed,
}

#[derive(Debug, Clone,Copy, PartialEq, Eq)]
pub enum MigrationType{
    Standard,
    Passive,
    ReusedCID,
}

impl fmt::Display for MigrationStatus{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        match self {
            MigrationStatus::Success => write!(f, "Success"),
            MigrationStatus::Failed => write!(f, "Failed"),
            MigrationStatus::Migrated => write!(f, "Migrated"),
        }
    }
}

impl fmt::Display for MigrationType{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        match self {
            MigrationType::Standard => write!(f, "Standard"),
            MigrationType::Passive => write!(f, "Passive"),
            MigrationType::ReusedCID => write!(f, "ReusedCID"),
        }
    }
}

pub struct TestResult{
    pub url: String,
    pub peer_addr: Option<SocketAddr>,
    pub migration_type: MigrationType,
    pub handshake_done: bool,
    pub migrated: bool,
    pub server: Option<String>,
    pub migration_status: Option<MigrationStatus>,
    pub error: Option<TestError>,
    pub response_headers: Option<HashMap<String,String>>,
    pub duration: Option<Duration>,
    pub stats: Option<Stats>,
}

impl TestResult {
    pub fn from_target(target: &Target) -> TestResult{
        TestResult{
            url: target.domain.clone(),
            peer_addr: Some(SocketAddr::new(target.ip,target.port)),
            handshake_done: false,
            migration_type: MigrationType::Standard,
            migrated: false,
            server: None,
            migration_status: None,
            error: None,
            response_headers: None,
            duration: None,
            stats: None,
        }
    }
}

pub fn prepare_hdr(url: &str) -> Option<Vec<quiche::h3::Header>>{

    let url = match url::Url::from_str(&url) {
        Ok(val) => val,
        Err(e) => {
            panic!("Failed to parse addr for url {:?} reason : {:?}", url, e);
        }
    };

    let authority = match url.port() {
        Some(port) => format!("{}:{}", url.host_str().unwrap(), port),

        None => url.host_str().unwrap().to_string(),
    };
    return Some(vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
            quiche::h3::Header::new(b":authority", authority.as_bytes()),
            quiche::h3::Header::new(
                b":path",
                url[url::Position::BeforePath..].as_bytes(),
            ),
            quiche::h3::Header::new(b"user-agent", b"quiche"),
        ]);
}


fn format_stats(stats: &Stats) -> String{
    format!("{{\"lost\":{},\"sent_bytes\":{},\"recv_bytes\":{},\"paths\":{},\"migration_disabled\":{}}}", stats.lost, stats.sent_bytes, stats.recv_bytes, stats.paths_count, stats.peer_disable_active_migration)
}

impl fmt::Display for TestResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        let server = match &self.server {
            Some(val) => format!(",\"server\":\"{val}\""),
            None => format!("")
        };
        let migration_status = match &self.migration_status {
            Some(status) => format!(",\"migration_status\":\"{status}\""),
            None => format!("")
        };
        let peer_addr = match &self.peer_addr{
            Some(addr) => format!(",\"peer_addr\":\"{addr}\""),
            None => format!("")
        };
        let headers = match &self.response_headers{
            Some(hdrs) => {
                match hdrs.get("server"){
                    Some(val) => format!(",\"HTTP_server\":\"{val}\""),
                    None => format!("")
                }
            },
            None => format!("")
        };
        let duration = match &self.duration{
            Some(val) => format!(",\"duration\":\"{}\"", val.as_secs()*1000 + val.subsec_millis() as u64),
            None => format!("")
        };
        let stats = match &self.stats{
            Some(val) => format!(",\"conn_stats\":{}", format_stats(val)),
            None => format!("")
        };
        match &self.error {
            Some(err) => {
                match err {
                    TestError::ResolutionError => write!(f,"{{\"url\":\"{}\",\"error\":\"{:?}\"}}", self.url, err),
                    _ => write!(f,"{{\"url\":\"{}\",\"test_type\":\"{}\",\"error\":\"{:?}\",\"performed_handshake\":{},\"performed_migration\":{}{}{}{}{}{}{}}}", self.url, self.migration_type, err, self.handshake_done, self.migrated,peer_addr, migration_status, server, headers, duration, stats)
                }
            },
            None => write!(f,"{{\"url\":\"{}\",\"test_type\":\"{}\",\"performed_handshake\":{},\"performed_migration\":{}{}{}{}{}{}{}}}", self.url, self.migration_type, self.handshake_done, self.migrated, peer_addr, migration_status, server, headers, duration, stats)
        }
    }
}