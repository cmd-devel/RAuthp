use std::process::exit;

use base32ct::{Base32Upper, Encoding};
use clap::{arg, ArgMatches, Command};
use keyring::Keyring;
use lazy_static::lazy_static;
use otp::OtpGenerator;
use regex::Regex;

mod keyring;
mod otp;

const DEFAULT_INTERVAL: u64 = 30;
const DEFAULT_DIGITS: u8 = 6;

lazy_static! {
    static ref BASE32_REGEX: Regex = Regex::new(r"^[A-Z2-7]+=*$").unwrap();
}

const SUBCOMMAND_GEN: &'static str = "gen";
const SUBCOMMAND_ADD: &'static str = "add";
const SUBCOMMAND_DEL: &'static str = "del";

fn get_cli_args() -> Command {
    Command::new("rauthp")
        .about("CLI TOTP generator")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new(SUBCOMMAND_GEN).about("Generate TOTP codes"))
        .subcommand(
            Command::new(SUBCOMMAND_ADD)
                .about("Register an account")
                .arg_required_else_help(true)
                .arg(arg!(name: <NAME> "Account name"))
                .arg(arg!(secret: <SECRET> "Base32 encoded secret")),
        )
        .subcommand(
            Command::new(SUBCOMMAND_DEL)
                .about("Delete an account")
                .arg_required_else_help(true)
                .arg(arg!(name: <NAME> "Account name")),
        )
}

fn handle_gen_cmd(keyring: &Keyring) -> bool {
    let all_secrets = match keyring.get_all_secrets() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to generate the codes: {}", e);
            return false;
        }
    };
    println!("{} secrets found", all_secrets.len());
    let count_success = all_secrets
        .iter()
        .filter(|elt| {
            let decoded_secret = match Base32Upper::decode_vec(elt.secret()) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Failed to decode the secret returned by the keyring: {}", e);
                    return false;
                }
            };
            let otpgen = OtpGenerator::new(&decoded_secret, DEFAULT_INTERVAL, DEFAULT_DIGITS);
            match otpgen.generate() {
                Ok(code) => {
                    println!("{:<35}: {}", elt.name(), code);
                    true
                }
                Err(()) => {
                    eprintln!("{:<35}: Code generation error", elt.name());
                    false
                }
            }
        })
        .count();
    count_success == all_secrets.len()
}

fn check_base_32_string(input: &str) -> bool {
    if !BASE32_REGEX.is_match(input) {
        return false;
    }

    // Incomplete quantum
    if input.len() % 8 != 0 {
        return false;
    }

    // rfc4648: The last quantum can be completed with 0, 1, 3, 4 or 6 padding characters
    // so it can contain 2, 4, 5 or 7 data characters.
    match input.find("=") {
        Some(i) => {
            let characters_in_last_quantum = (i % 8) as u32;
            [2_u32, 4_u32, 5_u32, 7_u32].contains(&characters_in_last_quantum)
        }
        None => true,
    }
}

fn handle_add_cmd(keyring: &Keyring, cmd_args: &ArgMatches) -> bool {
    let name = cmd_args
        .get_one::<String>("name")
        .expect("Failed to parse the secret name");
    let secret = cmd_args
        .get_one::<String>("secret")
        .expect("Failed to parse the secret value");

    let secret = &secret.to_uppercase();
    if !check_base_32_string(&secret) {
        eprintln!("Invalid secret format, should be a valid base32 string");
        return false;
    }

    match keyring.store_secret(name, secret) {
        Ok(()) => println!("Secret added"),
        Err(e) => eprintln!("Failed to add the secret to the keyring: {}", e),
    };

    true
}

fn handle_del_cmd(keyring: &Keyring, cmd_args: &ArgMatches) -> bool {
    let name = cmd_args
        .get_one::<String>("name")
        .expect("Failed to parse the secret name");
    match keyring.delete_secret(name) {
        Ok(()) => {
            println!("Secret deleted");
            true
        }
        Err(e) => {
            eprintln!("Failed to delete the secret: {}", e);
            false
        }
    }
}

fn main() {
    let keyring = match Keyring::new() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Failed to connect to the keyring: {}", e);
            exit(1);
        }
    };

    let args = get_cli_args().get_matches();
    let res = match args.subcommand() {
        Some((SUBCOMMAND_GEN, _)) => handle_gen_cmd(&keyring),
        Some((SUBCOMMAND_ADD, cmd_args)) => handle_add_cmd(&keyring, cmd_args),
        Some((SUBCOMMAND_DEL, cmd_args)) => handle_del_cmd(&keyring, cmd_args),
        _ => unreachable!(),
    };

    if !res {
        exit(1);
    }
}
