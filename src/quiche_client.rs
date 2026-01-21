use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;

use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;
use std::vec;

use crate::common::*;

use mio::net::UdpSocket;
use mio::Events;
use mio::Poll;
use quiche::h3::NameValue;
use quiche::h3::Header;
use quiche::Config;
use ring::rand::*;
use url::ParseError;
use url::Url;


const MAX_DATAGRAM_SIZE: usize = 1350;
const HTTP_3: [&[u8]; 1] = [b"h3"];

pub struct QuicheClient{
    buf: [u8; 65535],
    out: [u8; 1350],
    poll: Poll,
    events: Events,

    url: Url,
    pub peer_addr: SocketAddr,
    primary_socket: UdpSocket,
    migration_socket: UdpSocket,
    timeout: bool,
    end_now: bool,
    redirect: bool,
    
    config: Config,
    request_headers: Vec<Header>,
    response_headers: Option<HashMap<String,String>>,
    quiche_conn: Option<quiche::Connection>,
    h3_conn: Option<quiche::h3::Connection>,

    app_proto_selected: bool,
    path_validated: bool,
    new_path_probed: bool,
    
    migrations: u32,
    force_socket: u8,
    pub migration_status: Option<MigrationStatus>,

    keylog: Option<File>,
}

impl QuicheClient{
    pub fn init(target: &Target, primary_ip: Option<IpAddr>, migration_ip: Option<IpAddr>) -> Result<QuicheClient, TestError>{

        let buf = [0; 65535];
        let out = [0; MAX_DATAGRAM_SIZE];
    
        let url = match url::Url::from_str(&target.domain) {
            Ok(val) => val,
            Err(e) => {
                debug!("Failed to parse addr for url {:?} reason : {:?}", &target.domain, e);
                return Err(TestError::ResolutionError)
            }
        };

        let poll = mio::Poll::new().unwrap();
        let events = mio::Events::with_capacity(1024);


        let mut socket = if primary_ip.is_some() {
                match primary_ip.unwrap() {
                    IpAddr::V4(_) => mio::net::UdpSocket::bind(format!("{}:0",primary_ip.unwrap().to_string()).parse().unwrap()).unwrap(),
                    IpAddr::V6(_) => mio::net::UdpSocket::bind(format!("[{}]:0",primary_ip.unwrap().to_string()).parse().unwrap()).unwrap()
                }
        } else {
            mio::net::UdpSocket::bind(format!("0.0.0.0:0").parse().unwrap()).unwrap()
        };

        let peer_addr = SocketAddr::new(target.ip, target.port);
    
        poll.registry()
            .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
            .unwrap();
    
        let migrate_socket = if migration_ip.is_some() {
            let mut socket = 
                match migration_ip.unwrap() {
                    IpAddr::V4(_) => mio::net::UdpSocket::bind(format!("{}:0",migration_ip.unwrap().to_string()).parse().unwrap()).unwrap(),
                    IpAddr::V6(_) => mio::net::UdpSocket::bind(format!("[{}]:0",migration_ip.unwrap().to_string()).parse().unwrap()).unwrap(),
                };
            poll.registry()
                .register(&mut socket, mio::Token(1), mio::Interest::READABLE)
                .unwrap();
            socket
        } else {
            let mut socket = 
                match peer_addr {
                    SocketAddr::V4(_) => mio::net::UdpSocket::bind(format!("0.0.0.0:0").parse().unwrap()).unwrap(),
                    SocketAddr::V6(_) => mio::net::UdpSocket::bind(format!("[::]:0").parse().unwrap()).unwrap(),
                };
            poll.registry()
                .register(&mut socket, mio::Token(1), mio::Interest::READABLE)
                .unwrap();
            socket
        };

        let authority = match url.port() {
            Some(port) => format!("{}:{}", url.host_str().unwrap(), port),

            None => url.host_str().unwrap().to_string(),
        };
        let mut hdrs = vec![
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
                quiche::h3::Header::new(b":authority", authority.as_bytes()),
                quiche::h3::Header::new(
                    b":path",
                    url[url::Position::BeforePath..].as_bytes(),
                ),
            ];
        hdrs.extend(get_browser_headers());

        let mut config = quiche::Config::new(u32::from_str_radix("1", 16).unwrap()).unwrap();
        config.verify_peer(false);
    
        config.set_application_protos(&HTTP_3.to_vec()).unwrap();
    
        config.set_max_idle_timeout(1000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
    
        config.set_max_connection_window(25165824);
        config.set_max_stream_window(16777216);
    
        let mut keylog = None;
    
        if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(keylog_path)
                .unwrap();
            keylog = Some(file);
            config.log_keys();
        }
    
        config.grease(false);
        

        return Ok(QuicheClient{
            buf,
            out,
            poll,
            events,
            peer_addr,
            primary_socket: socket,
            migration_socket: migrate_socket,
            config,
            request_headers: hdrs,
            response_headers: None,
            quiche_conn: None,
            h3_conn: None,
            keylog,
            timeout: false,
            redirect: false,
            app_proto_selected: false,
            new_path_probed: false,
            path_validated: false,
            migration_status: None,
            migrations: 0,
            force_socket: 0,
            url,
            end_now: false,
        });
    }
    
    pub fn connect(&mut self) -> Result<(), TestError>{

        if self.quiche_conn.is_some() && self.quiche_conn.as_mut().unwrap().is_established(){
            return Ok(());
        }


        self.primary_socket.connect(self.peer_addr).expect("Failed to connect socket");
        self.migration_socket.connect(self.peer_addr).expect("Failed to connect socket");

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        let rng = SystemRandom::new();
        rng.fill(&mut scid[..]).unwrap();
    
        let scid = quiche::ConnectionId::from_ref(&scid);
    
        let local_addr = self.primary_socket.local_addr().unwrap();
    
        let conn = quiche::connect(
            self.url.domain(),
            &scid,
            local_addr,
            self.peer_addr,
            &mut self.config,);
        self.quiche_conn = match conn {
            Ok(val) => Some(val),
            Err(_) => return Err(TestError::ConnectionError)
        };
    
        if let Some(keylog) = &mut self.keylog {
            if let Ok(keylog) = keylog.try_clone() {
                self.quiche_conn.as_mut().unwrap().set_keylog(Box::new(keylog));
            }
        }
        

        debug!(
            "connecting to {:} from {:} with scid {:?}",
            self.peer_addr,
            self.primary_socket.local_addr().unwrap(),
            scid,
        );

        while self.quiche_conn.as_mut().unwrap().source_cids_left() > 0 {
            let (scid, reset_token) = generate_cid_and_reset_token(&rng);

            if self.quiche_conn.as_mut().unwrap().new_source_cid(&scid, reset_token, false).is_err() {
                break;
            }
            debug!("Added connectionID");
        }

        while !self.quiche_conn.as_mut().unwrap().is_established(){
            match self.flush_output(self.force_socket){
                Err(e) => return Err(e),
                _ => ()
            }
            match self.process_input(){
                Err(e) => return Err(e),
                _ => ()
            }
            self.handle_path_events();
        }

        debug!("Connection established");

        return Ok(());
    }

    pub fn perform_request(&mut self, custom_headers: &Option<Vec<Header>>, file: &mut Option<File>, migrate: bool, migration_type: Option<MigrationType>, full_request: bool) -> Result<Option<HashMap<String, String>>, TestError>{

        if self.quiche_conn.as_mut().unwrap().is_closed() {
            self.quiche_conn = None;
            self.timeout = false;
            info!("Connection is closed, reconnecting");
            match self.connect() {
                Ok(()) => info!("Reconnected"),
                Err(e) => return Err(e)
            }
            self.h3_conn = None;
        }
        if self.h3_conn.is_none() {
            self.h3_conn = Some(
                quiche::h3::Connection::with_transport(&mut self.quiche_conn.as_mut().unwrap(), &quiche::h3::Config::new().unwrap()).expect("Failed to create HTTP connection")
            );
        } 
        let stream_id = match custom_headers{
            Some(hdrs) => {
                match self.h3_conn.as_mut().unwrap().send_request(self.quiche_conn.as_mut().unwrap(), &hdrs, true){
                    Ok(val) => val,
                    Err(e) => {
                        debug!("{:?}", e);
                        return Err(TestError::HTTPError)
                    }
                }
            },
            None => {
                match self.h3_conn.as_mut().unwrap().send_request(self.quiche_conn.as_mut().unwrap(), &self.request_headers, true){
                    Ok(val) => val,
                    Err(e) => {
                        debug!("{:?}", e);
                        return Err(TestError::HTTPError)
                    }
                }
            }
        };
        debug!("sent request id: {}", stream_id);
        while !self.quiche_conn.as_mut().unwrap().is_closed() && !self.quiche_conn.as_mut().unwrap().stream_finished(stream_id) && !self.end_now && !self.redirect{
            match self.flush_output(self.force_socket){
                Err(e) => return Err(e),
                _ => ()
            }
            match self.process_input(){
                Err(e) => return Err(e),
                _ => ()
            }
            self.handle_responses(file, migrate, migration_type, full_request);
        }
        debug!("Request performed");
        self.end_now = false;
        Ok(self.response_headers.clone())
    }

    pub fn perform_request_with_redirect(&mut self, custom_headers: Option<Vec<Header>>, file: &mut Option<File>, max_redirect: u32, migrate: bool, migration_type: Option<MigrationType>, full_request: bool) -> Result<Option<HashMap<String, String>>, TestError>{
        let mut new_headers = custom_headers;
        for _ in 0..max_redirect{
            match self.perform_request(&new_headers, file, migrate, migration_type, full_request){
                Ok(hdrs) => {
                    match hdrs{
                        Some(map) => {
                            new_headers = match self.update_hdrs(&map){
                                Ok(val) => val,
                                Err(e) => return Err(e)
                            };
                            if new_headers.is_none(){
                                return Ok(Some(map));
                            }
                            debug!("Following redirection. New headers: {:?}", new_headers);
                            self.redirect = false;
                        },
                        None => return Ok(None)
                    }
                },
                Err(e) => return Err(e)
            }
        }
        Err(TestError::TooManyRedirect)
    }

    pub fn probe_path_and_migrate(&mut self, migration_type: MigrationType) -> Result<MigrationStatus, TestError>{

        self.migrations += 1;

        if migration_type == MigrationType::Passive{
            self.force_socket = 2;
            return Ok(MigrationStatus::Migrated)
        }

        if !self.new_path_probed {
            while self.quiche_conn.as_mut().unwrap().available_dcids() <= 0{
                match self.flush_output(self.force_socket){
                    Err(e) => return Err(e),
                    _ => ()
                }
                match self.process_input(){
                    Err(e) => return Err(e),
                    _ => ()
                }
                self.handle_path_events();
            }
            let migration_ip = self.migration_socket.local_addr().unwrap();
            let err = self.quiche_conn.as_mut().unwrap().probe_path(migration_ip, self.peer_addr);
            if err.is_err(){
                return Err(TestError::MigrationError);
            }
            self.new_path_probed = true;
            debug!("Path probed");
        }

        let timeout = Instant::now();
        while !self.path_validated && timeout.elapsed().as_secs() < 1{
            if migration_type == MigrationType::Standard{
                match self.flush_output(self.force_socket){
                    Err(e) => return Err(e),
                    _ => ()
                }
            } else {
                match self.flush_primary_socket(){
                    Err(e) => return Err(e),
                    _ => ()
                }
            } 

            match self.process_input(){
                Err(e) => return Err(e),
                _ => ()
            }
            self.handle_path_events();
        }

        if !self.path_validated{
            debug!("Failed to validate path");
            return Ok(MigrationStatus::Failed)
        }


        let new_ip = if self.migrations % 2 == 0{
            self.primary_socket.local_addr().unwrap()
        } else {
            self.migration_socket.local_addr().unwrap()
        };
        let conn_id = match self.quiche_conn.as_mut().unwrap().migrate(new_ip, self.peer_addr){
            Err(_) => return Err(TestError::MigrationError),
            Ok(id) => id
        };

        info!("Migrated to {:?} ; new connectionID : {}", new_ip, conn_id);

        match self.flush_output(self.force_socket){
            Err(e) => Err(e),
            _ => Ok(MigrationStatus::Success)
        }
    }

    pub fn close(&mut self) -> Result<(), TestError>{
        match self.quiche_conn.as_mut().unwrap().close(true, 0x100, b"kthxbye") {
            Ok(_) | Err(quiche::Error::Done) => (),

            Err(e) => panic!("error closing conn: {:?}", e),
        }

        while !self.quiche_conn.as_mut().unwrap().is_closed(){
            match self.flush_output(self.force_socket){
                Err(e) => return Err(e),
                _ => ()
            }
            match self.process_input(){
                Err(e) => return Err(e),
                _ => ()
            }
        }

        debug!("Connection closed");
        return Ok(());
    }

    fn handle_path_events(&mut self){

        let conn = self.quiche_conn.as_mut().unwrap();
        while let Some(qe) = conn.path_event_next() {
            match qe {
                quiche::PathEvent::New(..) => unreachable!(),

                quiche::PathEvent::Validated(local_addr, peer_addr) => {
                    info!(
                        "Path ({}, {}) is now validated",
                        local_addr, peer_addr
                    );
                    self.path_validated = true;
                },

                quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                    info!(
                        "Path ({}, {}) failed validation",
                        local_addr, peer_addr
                    );
                },

                quiche::PathEvent::Closed(local_addr, peer_addr) => {
                    info!(
                        "Path ({}, {}) is now closed and unusable",
                        local_addr, peer_addr
                    );
                },

                quiche::PathEvent::ReusedSourceConnectionId(
                    cid_seq,
                    old,
                    new,
                ) => {
                    info!(
                        "Peer reused cid seq {} (initially {:?}) on {:?}",
                        cid_seq, old, new
                    );
                },
                quiche::PathEvent::PeerMigrated(..) => unreachable!(),
            }
        }
    }

    fn process_input(&mut self) -> Result<(),TestError>{
        let conn = self.quiche_conn.as_mut().unwrap();

        if !conn.is_in_early_data() || self.app_proto_selected {
            self.poll.poll(&mut self.events, Some(Duration::from_secs(5))).unwrap();
        }

        if self.events.is_empty() {
            if self.timeout{
                return Err(TestError::Timeout);
            }
            conn.on_timeout();
            self.timeout = true;
        }

        for event in &self.events {
            let socket = match event.token() {
                mio::Token(0) => &self.primary_socket,

                mio::Token(1) => &self.migration_socket,

                _ => unreachable!(),
            };

            let local_addr = socket.local_addr().unwrap();
            'read: loop {
                let (len, from) = match socket.recv_from(&mut self.buf) {
                    Ok(v) => v,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("{}: recv() would block", local_addr);
                            break 'read;
                        }
                        debug!("Failed to receive on socket {:?}", socket);
                        return Err(TestError::ReadError);
                    },
                };

                debug!("{}: got {} bytes", local_addr, len);

                let recv_to = if self.force_socket == 2{
                    self.primary_socket.local_addr().unwrap()
                } else {
                    local_addr
                };
                let recv_info = quiche::RecvInfo {
                    to: recv_to,
                    from,
                };

                let pkt_buf = &mut self.buf[..len];
        
                let hdr = match quiche::Header::from_slice(
                    pkt_buf,
                    quiche::MAX_CONN_ID_LEN,
                ) {
                    Ok(v) => v,
    
                    Err(e) => {
                        debug!("Parsing packet header failed: {:?}", e);
                        continue 'read;
                    },
                };
    
                debug!("got packet {:?}", hdr);

                let read = match conn.recv(&mut self.buf[..len], recv_info) {
                    Ok(v) => v,

                    Err(_) => {
                        debug!("Error processing packets");
                        continue 'read;
                    },
                };
                debug!("{}: processed {} bytes", local_addr, read);
            }
        }
        debug!("done reading");
        return Ok(());
    }

    fn flush_output(&mut self, force_socket:u8) -> Result<(), TestError>{
        let conn = self.quiche_conn.as_mut().unwrap();
        let primary_addr = self.primary_socket.local_addr().unwrap();
        let migration_addr = self.migration_socket.local_addr().unwrap();

        loop {
            let (write, send_info) = match conn.send(
                &mut self.out,
            ) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!(
                        "done writing",
                    );
                    break;
                },

                Err(_) => {
                    return Err(TestError::SendError);
                },
            };

            let sock = if force_socket == 1{
                &self.primary_socket
            } else if force_socket == 2{
                &self.migration_socket
            } else if send_info.from == primary_addr{
                &self.primary_socket
            } else if send_info.from == migration_addr{
                &self.migration_socket
            } else{
                panic!("Could not find socket matching send address");
            };

            debug!("info_to = {:?}", send_info.to);

            if let Err(e) = sock.send(&self.out[..write]) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!(
                        "{} -> {}: send() would block",
                        send_info.from,
                        send_info.to
                    );
                    break;
                }
            }
            debug!(
                "{} -> {}: written {}",
                send_info.from,
                send_info.to,
                write
            );
        }

        return Ok(());
    }

    fn flush_primary_socket(&mut self) -> Result<(), TestError>{

        let conn = self.quiche_conn.as_mut().unwrap();
        let sock = &self.primary_socket;

        loop {
            let (write, send_info) = match conn.send(
                &mut self.out,
            ) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!(
                        "done writing",
                    );
                    break;
                },

                Err(_) => {
                    return Err(TestError::SendError);
                },
            };

            if let Err(e) = sock.send_to(&self.out[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!(
                        "{} -> {}: send() would block",
                        sock.local_addr().unwrap(),
                        send_info.to
                    );
                    break;
                }
            }
            debug!(
                "{} -> {}: written {}",
                sock.local_addr().unwrap(),
                send_info.to,
                write
            );
        }

        return Ok(())
    }

    fn update_hdrs(&mut self, response_hdrs: &HashMap<String,String>)-> Result<Option<Vec<Header>>, TestError>{
        debug!("{:?}", response_hdrs);
        let status = match response_hdrs.get(":status") {
            Some(val) => val,
            None => panic!("Unknown status") 
        };
        if status.starts_with("2"){
            return Ok(None);
        }

        match response_hdrs.get("location") {
            Some(url) => {

                let new_url;
                if url.starts_with("http://") || url.starts_with("https://") {
                    self.url = match Url::parse(&url) {
                        Ok(val) => val,
                        Err(e) => {
                            error!("Failed to parse absolute redirect URL {} reason: {:?}", url, e);
                            return Err(TestError::HTTPError);
                        }
                    };
                    return Ok(prepare_hdr(&url))
                }
                else if url.starts_with("://") {
                    new_url = format!("{}{}", self.url.scheme(), &url);
                    self.url = match Url::parse(&new_url) {
                        Ok(val) => val,
                        Err(e) => {
                            error!("Failed to parse scheme-relative redirect URL {} reason: {:?}", url, e);
                            return Err(TestError::HTTPError);
                        }
                    };
                    return Ok(prepare_hdr(&new_url));
                }

                //At this point, URL start with either a domain.tld/something or /something or just something
                if url.starts_with("/") {
                    // For absolute paths, use only base (scheme + authority) without the path
                    let base = &self.url[..url::Position::BeforePath];
                    new_url = format!("{}{}", base, url);
                } else  { //Url does not start with /
                    let base = &self.url[..url::Position::BeforePath];
                    let path = self.url.path();
                    let folder = if let Some(pos) = path.rfind('/') {
                        &path[..=pos]
                    } else {
                        "/"
                    };
                    new_url = format!("{}{}{}", base, folder, url);
                }
                self.url = match Url::parse(&new_url){
                    Ok(val) => val,
                    Err(e) => {
                        if e == ParseError::RelativeUrlWithoutBase{
                            let mut base = self.url.to_string();
                            base.push('/');
                            base.push_str(&new_url);
                            match Url::parse(&base){
                                Ok(val) => val,
                                Err(e) => {
                                    error!("Failed to parse redirect url {:?} reason : {:?}", &new_url, e);
                                    return Err(TestError::ResolutionError);
                                }
                            }
                        } else {
                            error!("Failed to parse redirect url {:?} reason : {:?}", &new_url, e);
                            return Err(TestError::ResolutionError);
                        }
                        
                    }
                };
                return Ok(prepare_hdr(&new_url))
            },
            None => ()
        };

        debug!("Failed to redirect request : {:?}", response_hdrs);
        Err(TestError::HTTPError)
    }
    
    fn handle_responses(&mut self,  file: &mut Option<File>, migrate: bool, migration_type: Option<MigrationType>, full_request: bool) {
        loop {
            match self.h3_conn.as_mut().unwrap().poll(self.quiche_conn.as_mut().unwrap()) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    debug!(
                        "got response headers {:?} on stream id {}",
                        (&list),
                        stream_id
                    );
                    let header_map: HashMap<String,String> = list.iter()
                        .map(|h| {
                            let name = String::from_utf8_lossy(h.name()).to_string();
                            let value = String::from_utf8_lossy(h.value()).to_string();
                
                            (name, value)
                        })
                        .collect();

                    if header_map.get("location").is_some(){
                        debug!("Redirection detected");
                        self.redirect = true;
                        self.response_headers = Some(header_map);
                        break;
                    }

                    self.response_headers = Some(header_map);

                    if migrate{
                        match self.probe_path_and_migrate(migration_type.unwrap()){
                            Ok(status) => {
                                self.migration_status = Some(status);
                            }
                            Err(_) => {
                                ();
                            }
                        };
                    }
                    if !full_request{
                        info!("Done reading headers");
                        self.end_now = true;
                        break;
                    };
                },
    
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    while let Ok(read) =
                    self.h3_conn.as_mut().unwrap().recv_body(self.quiche_conn.as_mut().unwrap(), stream_id, &mut self.buf)
                    {
                        match file{
                            Some(ref mut fd) => {
                                fd.write_all(&self.buf[..read]).expect("Failed to write body to file");
                            },
                            None => ()
                        };
                        debug!(
                            "got {} bytes of response data on stream {}",
                            read, stream_id
                        );
                    }
                },
    
                Ok((_stream_id, quiche::h3::Event::Finished)) => {
                    debug!("stream {} finished", _stream_id);
                    break;
                },
    
                Ok((_stream_id, quiche::h3::Event::Reset(_))) => {
                    match self.quiche_conn.as_mut().unwrap().close(true, 0x100, b"kthxbye") {
                        Ok(_) | Err(quiche::Error::Done) => (),
    
                        Err(e) => panic!("error closing conn: {:?}", e),
                    }
                    break;
                },
    
                Ok((
                    prioritized_element_id,
                    quiche::h3::Event::PriorityUpdate,
                )) => {
                    info!(
                        "{} PRIORITY_UPDATE triggered for element ID={}",
                        self.quiche_conn.as_mut().unwrap().trace_id(),
                        prioritized_element_id
                    );
                },
    
                Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                    info!(
                        "{} got GOAWAY with ID {} ",
                        self.quiche_conn.as_mut().unwrap().trace_id(),
                        goaway_id
                    );
                },
    
                Err(quiche::h3::Error::Done) => {
                    debug!("Done reading h3");
                    break;
                },
    
                Err(_) => {
                    break;
                },
            }
        }
    }

    pub fn get_stats(&self) -> Option<quiche::Stats>{
        match self.quiche_conn.as_ref(){
            Some(conn) => Some(conn.stats()),
            None => None
        }
    }
}

fn generate_cid_and_reset_token<T: SecureRandom>(
    rng: &T,
) -> (quiche::ConnectionId<'static>, u128) {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid).unwrap();
    let scid = scid.to_vec().into();
    let mut reset_token = [0; 16];
    rng.fill(&mut reset_token).unwrap();
    let reset_token = u128::from_be_bytes(reset_token);
    (scid, reset_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    struct TestCase {
        name: &'static str,
        initial_url: &'static str,
        status: &'static str,
        location: Option<&'static str>,
        expected_result: TestExpectation,
    }

    enum TestExpectation {
        None,
        Redirect {
            expected_url: &'static str,
            expected_authority: &'static str,
            expected_path: &'static str,
        },
    }

    fn create_test_client(initial_url: &str) -> QuicheClient {
        let target = Target {
            domain: initial_url.to_string(),
            ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 443,
        };

        QuicheClient::init(&target, None, None).unwrap()
    }

    fn get_header_value(headers: &Option<Vec<Header>>, name: &[u8]) -> String {
        if let Some(hdrs) = headers {
            for hdr in hdrs {
                if hdr.name() == name {
                    return String::from_utf8_lossy(hdr.value()).to_string();
                }
            }
        }
        String::new()
    }

    macro_rules! test_update_hdrs_case {
        ($test_name:ident, $name:expr, $initial_url:expr, $status:expr, $location:expr, $expected:expr) => {
            #[test]
            fn $test_name() {
                let mut client = create_test_client($initial_url);
                let mut response_hdrs = HashMap::new();
                response_hdrs.insert(":status".to_string(), $status.to_string());

                if let Some(location) = $location {
                    response_hdrs.insert("location".to_string(), location.to_string());
                }

                let result = client.update_hdrs(&response_hdrs);

                match $expected {
                    TestExpectation::None => {
                        assert!(result.is_ok(), "Test '{}' failed: expected Ok(None), got error: {:?}", $name, result);
                        let result = result.unwrap();
                        assert!(result.is_none(), "Test '{}' failed: expected None, got Some", $name);
                    }
                    TestExpectation::Redirect { expected_url, expected_authority, expected_path } => {
                        assert!(result.is_ok(), "Test '{}' failed: expected Ok, got error: {:?}", $name, result);
                        let result = result.unwrap();
                        assert!(result.is_some(), "Test '{}' failed: expected Some, got None", $name);

                        let authority = get_header_value(&result, b":authority");
                        let path = get_header_value(&result, b":path");

                        assert_eq!(authority, expected_authority,
                            "Test '{}' failed: authority mismatch", $name);
                        assert_eq!(path, expected_path,
                            "Test '{}' failed: path mismatch", $name);
                        assert_eq!(client.url.as_str(), expected_url,
                            "Test '{}' failed: URL mismatch", $name);
                    }
                }
            }
        };
    }

    test_update_hdrs_case!(
        test_status_200_returns_none,
        "Status 200 returns None",
        "https://example.com/page",
        "200",
        None::<&str>,
        TestExpectation::None
    );

    test_update_hdrs_case!(
        test_status_201_returns_none,
        "Status 201 returns None",
        "https://example.com/page",
        "201",
        None::<&str>,
        TestExpectation::None
    );

    test_update_hdrs_case!(
        test_absolute_http_url,
        "Absolute HTTP URL",
        "https://example.com/old",
        "301",
        Some("http://redirect.com/new"),
        TestExpectation::Redirect {
            expected_url: "http://redirect.com/new",
            expected_authority: "redirect.com",
            expected_path: "/new",
        }
    );

    test_update_hdrs_case!(
        test_absolute_https_url,
        "Absolute HTTPS URL",
        "https://example.com/old",
        "302",
        Some("https://secure.com/secure"),
        TestExpectation::Redirect {
            expected_url: "https://secure.com/secure",
            expected_authority: "secure.com",
            expected_path: "/secure",
        }
    );

    test_update_hdrs_case!(
        test_scheme_relative_url,
        "Scheme-relative URL",
        "https://example.com/old",
        "301",
        Some("://redirect.com/new"),
        TestExpectation::Redirect {
            expected_url: "https://redirect.com/new",
            expected_authority: "redirect.com",
            expected_path: "/new",
        }
    );

    test_update_hdrs_case!(
        test_absolute_path,
        "Absolute path",
        "https://example.com/old/page",
        "301",
        Some("/new/location"),
        TestExpectation::Redirect {
            expected_url: "https://example.com/new/location",
            expected_authority: "example.com",
            expected_path: "/new/location",
        }
    );

    test_update_hdrs_case!(
        test_absolute_path_with_trailing_slash,
        "Absolute path with trailing slash in base",
        "https://example.com/old/",
        "301",
        Some("/new"),
        TestExpectation::Redirect {
            expected_url: "https://example.com/new",
            expected_authority: "example.com",
            expected_path: "/new",
        }
    );

    test_update_hdrs_case!(
        test_relative_path_with_folder,
        "Relative path with folder",
        "https://example.com/folder/page",
        "301",
        Some("other.html"),
        TestExpectation::Redirect {
            expected_url: "https://example.com/folder/other.html",
            expected_authority: "example.com",
            expected_path: "/folder/other.html",
        }
    );

    test_update_hdrs_case!(
        test_relative_path_without_folder,
        "Relative path without folder",
        "https://example.com/page",
        "301",
        Some("other.html"),
        TestExpectation::Redirect {
            expected_url: "https://example.com/other.html",
            expected_authority: "example.com",
            expected_path: "/other.html",
        }
    );

    test_update_hdrs_case!(
        test_relative_path_with_subfolders,
        "Relative path with subfolders",
        "https://example.com/a/b/c/page",
        "301",
        Some("file.html"),
        TestExpectation::Redirect {
            expected_url: "https://example.com/a/b/c/file.html",
            expected_authority: "example.com",
            expected_path: "/a/b/c/file.html",
        }
    );

    test_update_hdrs_case!(
        test_absolute_path_with_query_string,
        "Absolute path with query string",
        "https://example.com/page?param=value",
        "301",
        Some("/new?other=param"),
        TestExpectation::Redirect {
            expected_url: "https://example.com/new?other=param",
            expected_authority: "example.com",
            expected_path: "/new?other=param",
        }
    );

    test_update_hdrs_case!(
        test_relative_path_with_query_string,
        "Relative path with query string",
        "https://example.com/folder/page",
        "301",
        Some("other.html?key=value"),
        TestExpectation::Redirect {
            expected_url: "https://example.com/folder/other.html?key=value",
            expected_authority: "example.com",
            expected_path: "/folder/other.html?key=value",
        }
    );

    test_update_hdrs_case!(
        test_with_custom_port,
        "With custom port",
        "https://example.com:8443/page",
        "301",
        Some("/new"),
        TestExpectation::Redirect {
            expected_url: "https://example.com:8443/new",
            expected_authority: "example.com:8443",
            expected_path: "/new",
        }
    );

    test_update_hdrs_case!(
        test_with_fragment,
        "With fragment",
        "https://example.com/page",
        "301",
        Some("/new#section"),
        TestExpectation::Redirect {
            expected_url: "https://example.com/new#section",
            expected_authority: "example.com",
            expected_path: "/new#section",
        }
    );
}
