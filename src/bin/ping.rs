use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use ping_tokio::{generate_payload, send_icmp_echo_v4, send_icmp_echo_v6, IcmpSocket};

struct Args {
    /// Original destination string as typed by the user (for display).
    dest_str: String,
    /// Number of echo requests to send.
    count: u32,
    /// Total ICMP payload size in bytes (must be > 8; first 8 are timestamp).
    size: u16,
    /// Per-probe receive timeout.
    timeout: Duration,
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().collect();
    let prog = argv.first().map(String::as_str).unwrap_or("ping");

    let mut dest: Option<String> = None;
    let mut count: u32 = 5;
    let mut size: u16 = 56;
    let mut timeout_secs: u64 = 1;

    let mut i = 1usize;
    while i < argv.len() {
        match argv[i].as_str() {
            "-c" => {
                i += 1;
                count = argv
                    .get(i)
                    .ok_or("-c requires an argument")?
                    .parse()
                    .map_err(|e| format!("-c: {e}"))?;
            }
            "-s" => {
                i += 1;
                size = argv
                    .get(i)
                    .ok_or("-s requires an argument")?
                    .parse()
                    .map_err(|e| format!("-s: {e}"))?;
            }
            "-W" => {
                i += 1;
                timeout_secs = argv
                    .get(i)
                    .ok_or("-W requires an argument")?
                    .parse()
                    .map_err(|e| format!("-W: {e}"))?;
            }
            s if !s.starts_with('-') => {
                if dest.is_some() {
                    return Err(format!("unexpected argument: {s}"));
                }
                dest = Some(s.to_owned());
            }
            _ => {
                return Err(format!(
                    "usage: {prog} <destination> [-c count] [-s size] [-W timeout]"
                ));
            }
        }
        i += 1;
    }

    let dest_str = dest
        .ok_or_else(|| format!("usage: {prog} <destination> [-c count] [-s size] [-W timeout]"))?;

    if size <= 8 {
        return Err(
            "size must be greater than 8 (first 8 bytes are reserved for timestamp)".to_string(),
        );
    }

    Ok(Args {
        dest_str,
        count,
        size,
        timeout: Duration::from_secs(timeout_secs),
    })
}

async fn resolve(dest: &str) -> std::io::Result<IpAddr> {
    if let Ok(ip) = dest.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addrs: Vec<_> = tokio::net::lookup_host(format!("{dest}:0"))
        .await?
        .collect();
    addrs
        .first()
        .map(|a| a.ip())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address found"))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("ping: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = run(args).await {
        eprintln!("ping: {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> std::io::Result<()> {
    let dest_ip = resolve(&args.dest_str).await?;

    // "data bytes" in the header is the total ICMP payload size (our `size` parameter).
    println!(
        "PING {} ({}): {} data bytes",
        args.dest_str, dest_ip, args.size
    );

    let payload = generate_payload(args.size as usize - 8);

    let socket = match dest_ip {
        IpAddr::V4(_) => IcmpSocket::bind(Ipv4Addr::UNSPECIFIED).await?,
        IpAddr::V6(_) => IcmpSocket::bind(Ipv6Addr::UNSPECIFIED).await?,
    };
    socket.connect(dest_ip.to_string().as_str()).await?;

    let mut packets_rx: u32 = 0;
    let mut rtts: Vec<Duration> = Vec::with_capacity(args.count as usize);

    for seq in 0..args.count {
        let result = match dest_ip {
            IpAddr::V4(_) => send_icmp_echo_v4(&socket, &payload, seq as u16, args.timeout)
                .await
                .map(|r| (r.len, r.src_addr.to_string(), r.seq, r.ttl as u32, r.rtt)),
            IpAddr::V6(_) => send_icmp_echo_v6(&socket, &payload, seq as u16, args.timeout)
                .await
                .map(|r| (r.len, r.src_addr.to_string(), r.seq, r.hlim as u32, r.rtt)),
        };

        match result {
            Ok((len, src, reply_seq, ttl, rtt)) => {
                let rtt_ms = rtt.as_secs_f64() * 1000.0;
                println!(
                    "{len} bytes from {src}: icmp_seq={reply_seq} ttl={ttl} time={rtt_ms:.3} ms"
                );
                packets_rx += 1;
                rtts.push(rtt);
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                println!("Request timeout for icmp_seq {seq}");
            }
            Err(e) => return Err(e),
        }
    }

    let packets_tx = args.count;
    let loss_pct = if packets_tx == 0 {
        0.0f64
    } else {
        (packets_tx - packets_rx) as f64 / packets_tx as f64 * 100.0
    };

    println!();
    println!("--- {} ping statistics ---", args.dest_str);
    println!(
        "{packets_tx} packets transmitted, {packets_rx} packets received, {loss_pct:.1}% packet loss"
    );

    if !rtts.is_empty() {
        let min_ms = rtts.iter().min().unwrap().as_secs_f64() * 1000.0;
        let max_ms = rtts.iter().max().unwrap().as_secs_f64() * 1000.0;
        let avg_nanos = rtts.iter().map(|d| d.as_nanos() as u64).sum::<u64>() / rtts.len() as u64;
        let avg_ms = Duration::from_nanos(avg_nanos).as_secs_f64() * 1000.0;
        let variance = rtts
            .iter()
            .map(|d| {
                let diff = d.as_nanos() as i64 - avg_nanos as i64;
                (diff * diff) as u64
            })
            .sum::<u64>()
            / rtts.len() as u64;
        let stddev_ms = Duration::from_nanos(variance.isqrt()).as_secs_f64() * 1000.0;

        println!(
            "round-trip min/avg/max/stddev = {min_ms:.3}/{avg_ms:.3}/{max_ms:.3}/{stddev_ms:.3} ms"
        );
    }

    Ok(())
}
