#[macro_use]
extern crate derive_error;

#[macro_use]
extern crate log;

extern crate tempdir;

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
use std::fs::File;
use tempdir::TempDir;
use std::path::PathBuf;
use std::ffi::OsStr;
use std::iter::{IntoIterator, Iterator};
use std::fmt::Debug;

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

pub trait CommandRunner {
    fn run_command(&mut self, program: &str, args: &[&str]) -> Result<Output,Error>;
}

pub struct MockCommandRunner<'a> {
    counter: usize,
    tests_io: Vec<(&'a str, &'a [&'a str], Output)>
}

impl<'a> MockCommandRunner<'a> {
    fn new(tests_io : Vec<(&'a str, &'a [&'a str], Output)>) -> MockCommandRunner<'a> {
        MockCommandRunner {
            counter: 0,
            tests_io: tests_io
        }
    }
}

impl<'a> CommandRunner for MockCommandRunner<'a> {
    fn run_command(&mut self, program: &str, args: &[&str]) -> Result<Output,Error> {
        assert_eq!(program,self.tests_io[self.counter].0);
        for i in 0..args.len() {
            assert_eq!(args[0],self.tests_io[self.counter].1[i]);
        }
        let output = self.tests_io[self.counter].2.clone();
        self.counter += 1;
        Ok(output)
    }
}

pub struct KernelInterface<T: CommandRunner> {
    command_runner: T
}

/// Assemble a Command to generate a WireGuard private key on Linux
pub fn gen_wg_privkey_command_linux() -> Command {
    let mut privkey_command = Command::new("wg");
    privkey_command.arg("genkey").stdin(Stdio::null()).stdout(Stdio::piped());

    privkey_command
}

/// Assemble a Command to derive a WireGuard public key from a given private key on Linux.
/// Includes stdin.
pub fn gen_wg_pubkey_command_linux(privkey: &String) -> (Command, String) {
    let mut pubkey_command = Command::new("wg");
    pubkey_command.arg("pubkey").stdin(Stdio::piped()).stdout(Stdio::piped());

    (pubkey_command, String::clone(&privkey))
}

impl<T: CommandRunner> KernelInterface<T>{
    fn new(command_runner: T) -> KernelInterface<T>{
        KernelInterface {
            command_runner: command_runner
        }
    }

    fn get_neighbors_linux(&mut self) -> Result<Vec<(HwAddr, IpAddr)>, Error> {
        let output = self.command_runner.run_command("ip", &["neighbor"])?;
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
        self.command_runner.run_command(
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
        self.command_runner.run_command(
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
            let res = self.command_runner.run_command(program, args)?;
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
        let output = self.command_runner.run_command("ebtables", &["-L", "INPUT", "--Lc"])?;
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
            println!("len is: {}", len);
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
        /* We ask to create a new Command to run and it's up to us whether we should really run it.
         * The tests are supposed to take advantage of that and verify Commands without running
         * them. Non-test callers will benefit from being able to schedule when they wanna run and
         * to handle errors they way they want. Also, std::process::Command is a standard,
         * well-known struct.
         *
         * In this case we do run it cause we're a caller that really wants the command's results.
         */
        let priv_key_bytes = gen_wg_privkey_command_linux().output().unwrap().stdout;
        let priv_key = String::from_utf8(priv_key_bytes).unwrap();

        let (mut pubkey_command, pubkey_stdin) = gen_wg_pubkey_command_linux(&priv_key);

        let pubkey_child = pubkey_command.spawn()?;
        pubkey_child.stdin.unwrap().write_all(pubkey_stdin.as_bytes()).unwrap();

        let mut my_pub_key = String::new();
        pubkey_child.stdout.unwrap().read_to_string(&mut my_pub_key)?;
        my_pub_key.pop();

        println!("getting remote key");
        let remote_pub_key = self.get_tunnel_key(&destination, &my_pub_key)?;
        println!("finished getting key");

        println!("geting local socket from pubkey");
        let local_sock = self.get_port_and_ip_from_key(&my_pub_key);
        println!("getting remote socket from pubkey");
        let remote_sock = self.get_port_and_ip_from_key(&remote_pub_key);

        self.setup_wg(&destination, &local_sock, &remote_sock, &priv_key, &remote_pub_key)?;

        Ok(())
    }

    pub fn setup_wg(
        &mut self,
        destination: &IpAddr,
        local_sock: &SocketAddrV6,
        remote_sock: &SocketAddrV6,
        priv_key: &String,
        remote_pub_key: &String) -> Result<(),Error> {

        let tmp_dir = TempDir::new("test")?;
        let file_path = tmp_dir.path().join("key");
        let mut key_file = File::create(file_path.clone())?;
        write!(key_file, "{}", priv_key)?;

        let links = self.command_runner.run_command("ip", &["link"])?;
        let links = String::from_utf8(links.stdout)?;
        let mut intf_num = 0;
        while ( links.contains(format!("wg{}",intf_num).as_str()) ){
            intf_num += 1;
        }
        let intf = format!("wg{}", intf_num);
        println!("adding link");
        self.command_runner.run_command("ip", &["link", "add", &intf, "type", "wireguard"])?;
        println!("adding addr");
        self.command_runner.run_command("ip", &["addr", "add", &format!("{}/48", local_sock.ip()), "dev", &intf])?; //, "peer", &format!("{}",remote_sock.ip())])?;
        self.command_runner.run_command("ip", &["addr", "add", &format!("fe80::{:x}:{:x}/64", local_sock.ip().segments()[6], local_sock.ip().segments()[7]), "dev", &intf])?;
        println!("setting link up");
        self.command_runner.run_command("ip", &["link", "set", &intf, "up"])?;
        println!("configuring wg");
        let output = self.command_runner.run_command("wg", &[
            "set",
            &intf,
            "private-key",
            &format!("{}", file_path.to_str().unwrap()),
            "listen-port",
            &format!("{}", local_sock.port()),
            "peer",
            &format!("{}", remote_pub_key),
            "endpoint",
            &format!("{}:{}", destination, remote_sock.port()),
            "allowed-ips",
            "::/0"])?;
        if !output.stderr.is_empty() {
            panic!("{}", String::from_utf8(output.stderr)?);
        }
        println!("done");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_wg_privkey_command_linux() {
        // If we want we can verify that the generated command is sane without
        // running it and changing machine state - exactly as we wanted
        let comm = gen_wg_privkey_command_linux();
        assert_eq!(format!("{:?}", comm), "\"wg\" \"genkey\"");
    }

    #[test]
    fn test_gen_wg_pubkey_command_linux() {
        // Here's an example where we actually run the command - unlike the tests we'll
        // ultimately want. This is just an example
        let privkey = String::from("4OIqHrSRSMiqNwG6Jh0oRQCCIJk3ORRb+KPz8IgXmk4=");
        let (mut comm, comm_stdin) = gen_wg_pubkey_command_linux(&privkey);
        assert_eq!(format!("{:?}", comm), "\"wg\" \"pubkey\"");
        assert_eq!(comm_stdin, privkey);

        // Now, let's see an example of how the generated commands can be used by the caller
        let expected_pubkey = String::from("Rq9KRqCbgmBBcnZseI67tkjSdovl43h+9Gt7gCZXHEk=");

        // We run the command
        let mut running_comm = comm.spawn().unwrap();

        // We fill its stdin as prescribed by the command generator in the second tuple member
        running_comm.stdin.unwrap().write_all(comm_stdin.as_bytes()).unwrap();

        // We retrieve the command's output
        let mut actual_pubkey = String::new();
        running_comm.stdout.unwrap().read_to_string(&mut actual_pubkey);

        // We shave off the newline from the end
        let _ = actual_pubkey.pop();

        // Let's see if that's what we wanted
        assert_eq!(actual_pubkey, expected_pubkey);
    }

    #[test]
    fn test_get_neighbors_linux() {
        let test_output = Output {
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
                };
        let test_input : &[&str] = &["neighbor"];
        let test_program = "ip";
        let test_io = vec![(test_program, test_input, test_output)];
        let mut command_runner = MockCommandRunner::new(test_io);

        let mut ki = KernelInterface::new(command_runner);

        let addresses = ki.get_neighbors_linux().unwrap();

        assert_eq!(format!("{}", addresses[0].0), "0:0:0:AA:0:3");
        assert_eq!(format!("{}", addresses[0].1), "10.0.2.2");

        assert_eq!(format!("{}", addresses[1].0), "0:0:0:AA:0:5");
        assert_eq!(format!("{}", addresses[1].1), "10.0.1.2");

        assert_eq!(format!("{}", addresses[2].0), "0:0:0:AA:0:56");
        assert_eq!(format!("{}", addresses[2].1), "2001::2");
    }
    /*

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
    */
}
