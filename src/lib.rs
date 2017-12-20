#[macro_use]
extern crate derive_error;

#[macro_use]
extern crate log;

use std::str;
extern crate hwaddr;
extern crate regex;
extern crate itertools;
extern crate crypto;

use itertools::join;
use std::net::{IpAddr, Ipv6Addr, TcpStream, SocketAddr, SocketAddrV6};
use hwaddr::HwAddr;
use std::str::{FromStr, from_utf8, Utf8Error};
use regex::Regex;
use std::process::{Command, Output, ExitStatus, Stdio, ChildStdin};
use std::os::unix::process::ExitStatusExt;
use crypto::md5;
use crypto::digest::Digest;
use std::fmt::Write as FmtWrite;
use std::io::{self, Read, Write, BufReader, BufRead};
use std::error::Error as OError;

#[derive(Debug, Error)]
pub enum Error {
    Io(std::io::Error),
    UTF8(std::string::FromUtf8Error),
    ParseInt(std::num::ParseIntError),
    AddrParse(std::net::AddrParseError),
    StrUTF8(std::str::Utf8Error),
    #[error(msg_embedded, no_from, non_std)]
    RuntimeError(String),
}

pub struct KernelInterface {
    run_command: Box<FnMut(&str, &[&str]) -> Result<Output, Error>>,
}

impl KernelInterface {
    pub fn new() -> KernelInterface {
        KernelInterface {
            run_command: Box::new(|program, args| {
                let output = Command::new(program).args(args).output()?;
                trace!("Command {} {:?} returned: {:?}", program, args, output);
                return Ok(output);
            }),
        }
    }

    fn get_neighbors_linux(&mut self) -> Result<Vec<(HwAddr, IpAddr)>, Error> {
        let output = (self.run_command)("ip", &["neighbor"])?;
        trace!("Got {:?} from `ip neighbor`", output);

        let mut vec = Vec::new();
        let re = Regex::new(r"(\S*).*lladdr (\S*).*(REACHABLE|STALE|DELAY)").unwrap();
        for caps in re.captures_iter(&String::from_utf8(output.stdout)?) {
            trace!("Regex captured {:?}", caps);

            vec.push((
                caps.get(2).unwrap().as_str().parse::<HwAddr>()?,
                IpAddr::from_str(&caps[1])?,
            ));
        }
        trace!("Got neighbors {:?}", vec);
        Ok(vec)
    }

    fn start_flow_counter_linux(
        &mut self,
        source_neighbor: HwAddr,
        destination: IpAddr,
    ) -> Result<(), Error> {
        self.delete_flow_counter_linux(source_neighbor, destination)?;
        (self.run_command)(
            "ebtables",
            &[
                "-A",
                "INPUT",
                "-s",
                &format!("{}", source_neighbor),
                "-p",
                "IPV6",
                "--ip6-dst",
                &format!("{}", destination),
                "-j",
                "CONTINUE",
            ],
        )?;
        Ok(())
    }

    fn start_destination_counter_linux(
        &mut self,
        destination: IpAddr,
    ) -> Result<(), Error> {
        self.delete_destination_counter_linux(destination)?;
        (self.run_command)(
            "ebtables",
            &[
                "-A",
                "INPUT",
                "-p",
                "IPV6",
                "--ip6-dst",
                &format!("{}", destination),
                "-j",
                "CONTINUE",
            ],
        )?;
        Ok(())
    }


    fn delete_ebtables_rule(
        &mut self,
        args: &[&str]
    ) -> Result<(), Error> {
        let loop_limit = 100;
        for _ in 0..loop_limit {
            let program = "ebtables";
            let res = (self.run_command)(program, args)?;
            // keeps looping until it is sure to have deleted the rule
            if res.stderr == b"Sorry, rule does not exist.\n".to_vec() {
                return Ok(());
            }
            if res.stdout == b"".to_vec() {
                continue;
            } else {
                return Err(Error::RuntimeError(
                    format!("unexpected output from {} {:?}: {:?}", program, join(args, " "), String::from_utf8_lossy(&res.stdout)),
                ))
            }
        }
        Err(Error::RuntimeError(
            format!("loop limit of {} exceeded", loop_limit)
        ))
    }

    fn delete_flow_counter_linux(
        &mut self,
        source_neighbor: HwAddr,
        destination: IpAddr,
    ) -> Result<(), Error> {
        self.delete_ebtables_rule(&[
            "-D",
            "INPUT",
            "-s",
            &format!("{}", source_neighbor),
            "-p",
            "IPV6",
            "--ip6-dst",
            &format!("{}", destination),
            "-j",
            "CONTINUE",
        ])
    }

    fn delete_destination_counter_linux(
        &mut self,
        destination: IpAddr,
    ) -> Result<(), Error> {
        self.delete_ebtables_rule(&[
            "-D",
            "INPUT",
            "-p",
            "IPV6",
            "--ip6-dst",
            &format!("{}", destination),
            "-j",
            "CONTINUE",
        ])
    }

    fn read_flow_counters_linux(&mut self) -> Result<Vec<(HwAddr, IpAddr, u64)>, Error> {
        let output = (self.run_command)("ebtables", &["-L", "INPUT", "--Lc"])?;
        let mut vec = Vec::new();
        let re = Regex::new(r"-s (.*) --ip6-dst (.*)/.* bcnt = (.*)").unwrap();
        for caps in re.captures_iter(&String::from_utf8(output.stdout)?) {
            vec.push((
                caps[1].parse::<HwAddr>()?,
                IpAddr::from_str(&caps[2])?,
                caps[3].parse::<u64>()?,
            ));
        }
        Ok(vec)
    }

    /// Returns a vector of neighbors reachable over layer 2, giving the hardware
    /// and IP address of each. Implemented with `ip neighbor` on Linux.
    pub fn get_neighbors(&mut self) -> Result<Vec<(HwAddr, IpAddr)>, Error> {
        if cfg!(target_os = "linux") {
            return self.get_neighbors_linux();
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }


    /// This starts a counter of bytes forwarded to a certain destination.
    /// If the destination already exists, it resets the counter.
    /// Implemented with `ebtables` on linux.
    pub fn start_destination_counter(
        &mut self,
        destination: IpAddr,
    ) -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            return self.start_destination_counter_linux(destination);
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }

    /// This deletes a counter of bytes forwarded to a certain destination.
    /// Implemented with `ebtables` on linux.
    pub fn delete_destination_counter(
        &mut self,
        destination: IpAddr,
    ) -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            return self.delete_destination_counter_linux(destination);
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }


    /// This starts a counter of the bytes used by a particular "flow", a
    /// Neighbor/Destination pair. If the flow already exists, it resets the counter.
    /// Implemented with `ebtables` on linux.
    pub fn start_flow_counter(
        &mut self,
        source_neighbor: HwAddr,
        destination: IpAddr,
    ) -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            return self.start_flow_counter_linux(source_neighbor, destination);
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }

    /// This deletes a counter of the bytes used by a particular "flow", a
    /// Neighbor/Destination pair.
    /// Implemented with `ebtables` on linux.
    pub fn delete_flow_counter(
        &mut self,
        source_neighbor: HwAddr,
        destination: IpAddr,
    ) -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            return self.delete_flow_counter_linux(source_neighbor, destination);
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }

    /// Returns a vector of traffic coming from a specific hardware address and going
    /// to a specific IP. Note that this will only track flows that have already been
    /// registered. Implemented with `ebtables` on Linux.
    pub fn read_flow_counters(&mut self) -> Result<Vec<(HwAddr, IpAddr, u64)>, Error> {
        if cfg!(target_os = "linux") {
            return self.read_flow_counters_linux();
        }

        Err(Error::RuntimeError(
            String::from("not implemented for this platform"),
        ))
    }

    fn get_tunnel_key(&mut self, neigh: &IpAddr, local_pubkey : &String) -> Result<String, Error> {
        let sockAddr = SocketAddr::new(neigh.clone(), 11492);
        let mut stream = TcpStream::connect(sockAddr)?;

        let mut reader = BufReader::new(stream);
        let mut buf : Vec<u8> = vec![0; 128];
        let mut bufStr = String::new();
        println!("reading header");
        reader.read_line(&mut bufStr);
        if bufStr.contains("ALTHEA") {
            stream = reader.into_inner();
            println!("sending request");
            let _ = stream.write(&[1])?;
            println!("reading response");
            let len = stream.read(&mut buf)?;
            buf.truncate(len);
            println!("sending pubkey");
            let _ = stream.write(local_pubkey.as_bytes());
            return Ok(String::from_utf8(buf)?);
        } else {
            Err(Error::RuntimeError(String::from("protocol mismatch")))
        }
    }

    pub fn get_port_and_ip_from_key(&mut self, pubkey: &String) -> SocketAddrV6 {
        let mut ipv6addr = String::from("fd01:1234:1234:1234");
        let mut hash = md5::Md5::new();
        hash.input(pubkey.as_bytes());
        let mut res : Vec<u8> = vec![0;16];
        hash.result(&mut res);
        for i in 0..8 {
            if i % 2 == 0 {
                write!(&mut ipv6addr, ":");
            }
            if res[i] < 16 {
                write!(&mut ipv6addr, "0");
            }
            write!(&mut ipv6addr, "{:x}", res[i]);
        }
        let port = (( (res[0] as u16) | (res[1] as u16) << 8) % 55535) + 10000;
        let addr = SocketAddrV6::new(Ipv6Addr::from_str(ipv6addr.as_str()).unwrap(), port, 0, 0);
        addr        
    }

    pub fn open_tunnel(&mut self, destination: IpAddr) -> Result<(),Error> {
        if cfg!(target_os = "linux") {
            return self.open_tunnel_linux(destination);
        }

        Err(Error::RuntimeError(String::from("not implemented for this platform")))
    }

    pub fn open_tunnel_linux(&mut self, destination: IpAddr) -> Result<(),Error> {
        let priv_key = String::from_utf8((self.run_command)("wg", &["genkey"])?.stdout).unwrap();
        let pub_key_proc = Command::new("wg").args(&["pubkey"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
        pub_key_proc.stdin.unwrap().write_all(priv_key.as_bytes()).unwrap();
        let mut my_pub_key = String::new();
        pub_key_proc.stdout.unwrap().read_to_string(&mut my_pub_key);
        println!("getting remote key");
        let remote_pub_key = self.get_tunnel_key(&destination, &my_pub_key)?;
        println!("finished getting key");

        println!("geting local socket from pubkey");
        let local_sock = self.get_port_and_ip_from_key(&my_pub_key);
        println!("getting remote socket from pubkey");
        let remote_sock = self.get_port_and_ip_from_key(&remote_pub_key);

        let links = (self.run_command)("ip", &["link"])?;
        let links = String::from_utf8(links.stdout)?;
        let mut intf_num = 0;
        while ( links.contains(format!("wg{}",intf_num).as_str()) ){
            intf_num += 1;
        }
        let intf = format!("wg{}", intf_num);
        println!("adding link");
        (self.run_command)("ip", &["link", "add", &intf, "type", "wireguard"])?;
        println!("adding addr");
        (self.run_command)("ip", &["addr", "add", &format!("{}", local_sock.ip()), "dev", &intf, "peer", &format!("{}",remote_sock.ip())])?;
        println!("setting link up");
        (self.run_command)("ip", &["link", "set", &intf, "up"])?;
        println!("configuring wg");
        let wg_proc = Command::new("wg").args(&[
            "set", 
            &intf, 
            "listen-port", 
            &format!("{}", local_sock.port()), 
            "peer", 
            &format!("{}", remote_pub_key), 
            "endpoint", 
            &format!("{}:{}", destination, remote_sock.port()), 
            "allowed-ips",
            "::/0"]).stdin(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        wg_proc.stdin.unwrap().write_all(priv_key.as_bytes())?;
        let mut res = String::new();
        wg_proc.stderr.unwrap().read_to_string(&mut res);
        if !res.is_empty() {
            panic!("{}", res);
        }
        println!("done");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_neighbors_linux() {
        let mut ki = KernelInterface {
            run_command: Box::new(|program, args| {
                assert_eq!(program, "ip");
                assert_eq!(args, &["neighbor"]);

                Ok(Output {
                    stdout: b"10.0.2.2 dev eth0 lladdr 00:00:00:aa:00:03 STALE
10.0.0.2 dev eth0  FAILED
10.0.1.2 dev eth0 lladdr 00:00:00:aa:00:05 REACHABLE
2001::2 dev eth0 lladdr 00:00:00:aa:00:56 REACHABLE
fe80::7459:8eff:fe98:81 dev eth0 lladdr 76:59:8e:98:00:81 STALE
fe80::433:25ff:fe8c:e1ea dev eth0 lladdr 1a:32:06:78:05:0a STALE
2001::2 dev eth0  FAILED"
                        .to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }),
        };

        let addresses = ki.get_neighbors_linux().unwrap();

        assert_eq!(format!("{}", addresses[0].0), "0:0:0:AA:0:3");
        assert_eq!(format!("{}", addresses[0].1), "10.0.2.2");

        assert_eq!(format!("{}", addresses[1].0), "0:0:0:AA:0:5");
        assert_eq!(format!("{}", addresses[1].1), "10.0.1.2");

        assert_eq!(format!("{}", addresses[2].0), "0:0:0:AA:0:56");
        assert_eq!(format!("{}", addresses[2].1), "2001::2");
    }

    #[test]
    fn test_read_flow_counter_linuxs() {
        let mut ki = KernelInterface {
            run_command: Box::new(|program, args| {
                assert_eq!(program, "ebtables");
                assert_eq!(args, &["-L", "INPUT", "--Lc"]);

                Ok(Output {
                    stdout:
b"Bridge table: filter

Bridge chain: INPUT, entries: 3, policy: ACCEPT
-p IPv6 -s 0:0:0:aa:0:2 --ip6-dst 2001::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff -j ACCEPT , pcnt = 1199 -- bcnt = 124696
-p IPv6 -s 0:0:0:aa:0:0 --ip6-dst 2001::3/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff -j ACCEPT , pcnt = 1187 -- bcnt = 123448
-p IPv6 -s 0:0:0:aa:0:0 --ip6-dst 2001::3/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff -j ACCEPT , pcnt = 0 -- bcnt = 0"
                        .to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }),
        };

        let traffic = ki.read_flow_counters_linux().unwrap();

        assert_eq!(format!("{}", traffic[0].0), "0:0:0:AA:0:2");
        assert_eq!(format!("{}", traffic[0].1), "2001::1");
        assert_eq!(traffic[0].2, 124696);

        assert_eq!(format!("{}", traffic[1].0), "0:0:0:AA:0:0");
        assert_eq!(format!("{}", traffic[1].1), "2001::3");
        assert_eq!(traffic[1].2, 123448);
    }

    #[test]
    fn test_delete_counter_linux() {
        let mut counter = 0;
        let delete_rule = &[
            "-D",
            "INPUT",
            "-s",
            "0:0:0:AA:0:2",
            "-p",
            "IPV6",
            "--ip6-dst",
            "2001::3",
            "-j",
            "CONTINUE",
        ];
        let mut ki = KernelInterface {
            run_command: Box::new(move |program, args| {
                assert_eq!(program, "ebtables");

                counter = counter + 1;
                println!("COUNTER {}", counter);
                match counter {
                    1 => {
                        assert_eq!(args, delete_rule);
                        Ok(Output {
                            stdout: b"".to_vec(),
                            stderr: b"".to_vec(),
                            status: ExitStatus::from_raw(0),
                        })
                    }
                    2 => {
                        assert_eq!(args, delete_rule);
                        Ok(Output {
                            stdout: b"".to_vec(),
                            stderr: b"".to_vec(),
                            status: ExitStatus::from_raw(0),
                        })
                    }
                    3 => {
                        assert_eq!(args, delete_rule);
                        Ok(Output {
                            stdout: b"".to_vec(),
                            stderr: b"Sorry, rule does not exist.\n".to_vec(),
                            status: ExitStatus::from_raw(0),
                        })
                    }
                    _ => panic!("run_command called too many times"),

                }

            }),
        };
        ki.delete_flow_counter_linux(
            "0:0:0:aa:0:2".parse::<HwAddr>().unwrap(),
            "2001::3".parse::<IpAddr>().unwrap(),
        ).unwrap();

        let mut ki = KernelInterface {
            run_command: Box::new(move |_, _| {
                counter = counter + 1;
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }),
        };

        match ki.delete_flow_counter_linux(
            "0:0:0:aa:0:2".parse::<HwAddr>().unwrap(),
            "2001::3".parse::<IpAddr>().unwrap(),
        ) {
            Err(e) => assert_eq!(e.to_string(), "loop limit of 100 exceeded"),
            _ => panic!("no loop limit error")
        }

        let mut ki = KernelInterface {
            run_command: Box::new(move |_, _| {
                counter = counter + 1;
                Ok(Output {
                    stdout: b"shibby".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }),
        };

        match ki.delete_flow_counter_linux(
            "0:0:0:aa:0:2".parse::<HwAddr>().unwrap(),
            "2001::3".parse::<IpAddr>().unwrap(),
        ) {
            Err(e) => assert_eq!(e.to_string(), "unexpected output from ebtables \"-D INPUT -s 0:0:0:AA:0:2 -p IPV6 --ip6-dst 2001::3 -j CONTINUE\": \"shibby\""),
            _ => panic!("no unexpeted input error")
        }
    }

    #[test]
    fn test_start_counter_linux() {
        let mut counter = 0;
        let delete_rule = &[
            "-D",
            "INPUT",
            "-s",
            "0:0:0:AA:0:2",
            "-p",
            "IPV6",
            "--ip6-dst",
            "2001::3",
            "-j",
            "CONTINUE",
        ];
        let add_rule = &[
            "-A",
            "INPUT",
            "-s",
            "0:0:0:AA:0:2",
            "-p",
            "IPV6",
            "--ip6-dst",
            "2001::3",
            "-j",
            "CONTINUE",
        ];
        let mut ki = KernelInterface {
            run_command: Box::new(move |program, args| {
                assert_eq!(program, "ebtables");

                counter = counter + 1;
                println!("COUNTER {}", counter);
                match counter {
                    1 => {
                        assert_eq!(args, delete_rule);
                        Ok(Output {
                            stdout: b"".to_vec(),
                            stderr: b"Sorry, rule does not exist.\n".to_vec(),
                            status: ExitStatus::from_raw(0),
                        })
                    }
                    2 => {
                        assert_eq!(args, add_rule);
                        Ok(Output {
                            stdout: b"".to_vec(),
                            stderr: b"".to_vec(),
                            status: ExitStatus::from_raw(0),
                        })
                    }
                    _ => panic!("run_command called too many times"),

                }

            }),
        };

        ki.start_flow_counter_linux(
            "0:0:0:AA:0:2".parse::<HwAddr>().unwrap(),
            "2001::3".parse::<IpAddr>().unwrap(),
        ).unwrap();
    }

    #[test]
    fn test_open_tunnel() {
        let mut ki = KernelInterface::new();
        let res = ki.open_tunnel_linux("2001::2".parse::<IpAddr>().unwrap());
        match res {
            Ok(m) => println!("success"),
            Err(e) => panic!("error in open_tunnel: {}", e.cause().unwrap())
        }
    }

    #[test]
    fn test_get_port_and_ip_from_key() {
        let mut ki = KernelInterface::new();
        ki.get_port_and_ip_from_key(&String::from("CEJaNjYyx4puwMvjT67GjIGNfIeJfnEo9VsmvKXwElg="));
    }
}
