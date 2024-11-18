use std::net::IpAddr;

use crate::common::{MigrationStatus, MigrationType, Target, TestResult};
use crate::quiche_client::*;


pub fn test_migration(target: &Target, primary_ip: Option<IpAddr>, migration_ip: Option<IpAddr>, wait_headers: bool, migration_type: MigrationType, fast: bool) -> TestResult{
    let mut result: TestResult = TestResult::from_target(target);
    let mut client = match QuicheClient::init(target, primary_ip, migration_ip){
        Ok(client) => client,
        Err(e) => {
            result.error = Some(e);
            return result;
        }
    };

    match client.connect(){
        Ok(()) => (),
        Err(e) => {
            result.error = Some(e);
            return result;
        }
    }

    result.peer_addr = Some(client.peer_addr);
    result.handshake_done = true;

    if !wait_headers{
        let status = match client.probe_path_and_migrate(migration_type){
            Ok(status) => status,
            Err(e) => {
                result.error = Some(e);
                return result;
            }
        };
        if status != MigrationStatus::Failed{
            result.migrated = true;
        }
    }

    let response_headers = match client.perform_request_with_redirect(None, &mut None, 5, wait_headers, Some(migration_type), !fast){
        Ok(hdrs) => hdrs,
        Err(e) => {
            result.error = Some(e);
            return result;
        }
    };

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