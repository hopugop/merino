use merino::*;
use proptest::prelude::*;

fn response_code(code: u8) -> ResponseCode {
    match code {
        0 => ResponseCode::Success,
        1 => ResponseCode::Failure,
        2 => ResponseCode::RuleFailure,
        3 => ResponseCode::NetworkUnreachable,
        4 => ResponseCode::HostUnreachable,
        5 => ResponseCode::ConnectionRefused,
        6 => ResponseCode::TtlExpired,
        7 => ResponseCode::CommandNotSupported,
        _ => ResponseCode::AddrTypeNotSupported,
    }
}

fn command(code: u8) -> SockCommand {
    SockCommand::from(usize::from(code)).unwrap()
}

proptest! {
    /// Parsing arbitrary bytes must never panic.
    #[test]
    fn parsers_never_panic(data in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = parse_greeting(&data);
        let _ = parse_userpass(&data);
        let _ = parse_request(&data);
        let _ = parse_udp_header(&data);
        let _ = pretty_print_addr(&AddrType::V4, &data);
        let _ = pretty_print_addr(&AddrType::V6, &data);
        let _ = pretty_print_addr(&AddrType::Domain, &data);
    }

    /// A successful parse never claims to consume more than it was given.
    #[test]
    fn consumed_never_exceeds_input(data in prop::collection::vec(any::<u8>(), 0..256)) {
        if let Ok((_, _, _, consumed)) = parse_greeting(&data) {
            prop_assert!(consumed <= data.len());
        }
        if let Ok((_, consumed)) = parse_userpass(&data) {
            prop_assert!(consumed <= data.len());
        }
        if let Ok((_, consumed)) = parse_request(&data) {
            prop_assert!(consumed <= data.len());
        }
        if let Ok((_, consumed)) = parse_udp_header(&data) {
            prop_assert!(consumed <= data.len());
        }
    }

    /// A parsed request's address always has the length implied by its type.
    #[test]
    fn parsed_addr_length_matches_type(data in prop::collection::vec(any::<u8>(), 0..256)) {
        if let Ok((req, _)) = parse_request(&data) {
            match req.addr_type {
                AddrType::V4 => prop_assert_eq!(req.addr.len(), 4),
                AddrType::V6 => prop_assert_eq!(req.addr.len(), 16),
                AddrType::Domain => prop_assert!(req.addr.len() <= 255),
            }
        }
    }

    /// Every well-formed IPv4 request round-trips through the parser.
    #[test]
    fn ipv4_request_roundtrip(ip in any::<[u8; 4]>(), port in any::<u16>(), cmd in 1u8..=3) {
        let mut frame = vec![0x05, cmd, 0x00, 0x01];
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&port.to_be_bytes());

        let (req, consumed) = parse_request(&frame).unwrap();
        prop_assert_eq!(consumed, frame.len());
        prop_assert_eq!(req.command, command(cmd));
        prop_assert_eq!(req.addr_type, AddrType::V4);
        prop_assert_eq!(req.addr, ip.to_vec());
        prop_assert_eq!(req.port, port);
    }

    /// Every well-formed IPv6 request round-trips through the parser.
    #[test]
    fn ipv6_request_roundtrip(ip in any::<[u8; 16]>(), port in any::<u16>(), cmd in 1u8..=3) {
        let mut frame = vec![0x05, cmd, 0x00, 0x04];
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&port.to_be_bytes());

        let (req, consumed) = parse_request(&frame).unwrap();
        prop_assert_eq!(consumed, frame.len());
        prop_assert_eq!(req.command, command(cmd));
        prop_assert_eq!(req.addr_type, AddrType::V6);
        prop_assert_eq!(req.addr, ip.to_vec());
        prop_assert_eq!(req.port, port);
    }

    /// Every well-formed domain request round-trips through the parser.
    #[test]
    fn domain_request_roundtrip(
        domain in prop::collection::vec(any::<u8>(), 0..=255),
        port in any::<u16>(),
        cmd in 1u8..=3,
    ) {
        let mut frame = vec![0x05, cmd, 0x00, 0x03, domain.len() as u8];
        frame.extend_from_slice(&domain);
        frame.extend_from_slice(&port.to_be_bytes());

        let (req, consumed) = parse_request(&frame).unwrap();
        prop_assert_eq!(consumed, frame.len());
        prop_assert_eq!(req.addr_type, AddrType::Domain);
        prop_assert_eq!(req.addr, domain);
        prop_assert_eq!(req.port, port);
    }

    /// The reply is always the exact 10-byte RFC 1928 layout.
    #[test]
    fn reply_is_always_ten_bytes(code in 0u8..=8) {
        let reply = SocksReply::new(response_code(code));
        prop_assert_eq!(reply.as_bytes().len(), 10);
        prop_assert_eq!(reply.as_bytes()[0], 0x05);
        prop_assert_eq!(reply.as_bytes()[1], code);
        prop_assert_eq!(reply.as_bytes()[2], 0x00);
    }

    /// Address/command parsing is total: no input can make it panic.
    #[test]
    fn addr_and_command_parsers_are_total(n in any::<usize>()) {
        let _ = AddrType::from(n);
        let _ = SockCommand::from(n);
    }
}
