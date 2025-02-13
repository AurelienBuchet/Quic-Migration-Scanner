use std::net::IpAddr;
use std::time::Instant;

use crate::common::{MigrationStatus, MigrationType, Target, TestResult};
use crate::quiche_client::*;


pub fn test_migration(target: &Target, primary_ip: Option<IpAddr>, migration_ip: Option<IpAddr>, wait_headers: bool, migration_type: Option<MigrationType>, fast: bool) -> TestResult{
    let mut result: TestResult = TestResult::from_target(target);

    let mut client = match QuicheClient::init(target, primary_ip, migration_ip){
        Ok(client) => client,
        Err(e) => {
            result.error = Some(e);
            return result;
        }
    };

    let start_time = Instant::now();
    match client.connect(){
        Ok(()) => (),
        Err(e) => {
            result.error = Some(e);
            return result;
        }
    }

    result.peer_addr = Some(client.peer_addr);
    result.handshake_done = true;

    if !wait_headers && migration_type.is_some(){
        let status = match client.probe_path_and_migrate(migration_type.unwrap()){
            Ok(status) => status,
            Err(e) => {
                result.duration = Some(start_time.elapsed());
                result.error = Some(e);
                return result;
            }
        };
        if status != MigrationStatus::Failed{
            result.migrated = true;
        }
    }

    let response_headers = match client.perform_request_with_redirect(None, &mut None, 5, wait_headers, migration_type, !fast){
        Ok(hdrs) => hdrs,
        Err(e) => {
            result.duration = Some(start_time.elapsed());
            result.error = Some(e);
            return result;
        }
    }; 
    result.duration = Some(start_time.elapsed());

    result.stats = client.get_stats();
    result.response_headers = response_headers;

    if client.migration_status.is_some(){
        result.migrated = true;
        result.migration_status = client.migration_status.clone();
    }



    if !fast{
        match client.close() {
            Ok(()) => (),
            Err(e) => {
                result.error = Some(e);
                return result;
            }
        };
    }
 
    result
}