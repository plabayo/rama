#![allow(dead_code)]

use std::{
    io::{BufRead, BufReader},
    process::Child,
    thread,
};

use base64::Engine;

#[derive(Debug)]
/// A wrapper around a rama service process.
pub(super) struct RamaService {
    process: Child,
}

impl RamaService {
    /// Start the rama Ip service with the given port.
    pub(super) fn ip(port: u16) -> Self {
        let mut process = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command()
            .stdout(std::process::Stdio::piped())
            .arg("ip")
            .arg("-p")
            .arg(port.to_string())
            .env("RUST_LOG", "info")
            .spawn()
            .unwrap();

        let stdout = process.stdout.take().unwrap();
        let mut stdout = BufReader::new(stdout).lines();

        for line in &mut stdout {
            let line = line.unwrap();
            if line.contains("ip service ready") {
                break;
            }
        }

        thread::spawn(move || {
            for line in stdout {
                let line = line.unwrap();
                eprintln!("rama ip >> {}", line);
            }
        });

        Self { process }
    }

    /// Start the rama echo service with the given port.
    pub(super) fn echo(port: u16, secure: bool, acme_data: Option<String>) -> Self {
        let mut builder = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command();

        if let Some(acme_data) = acme_data {
            builder.env("RAMA_ACME_DATA", acme_data);
        }

        if secure {
            const BASE64: base64::engine::GeneralPurpose =
                base64::engine::general_purpose::STANDARD;

            builder.env(
                "RAMA_TLS_CRT",
                BASE64.encode(include_bytes!("./example_tls.crt")),
            );
            builder.env(
                "RAMA_TLS_KEY",
                BASE64.encode(include_bytes!("./example_tls.key")),
            );
        }

        builder
            .stdout(std::process::Stdio::piped())
            .arg("echo")
            .arg("-p")
            .arg(port.to_string())
            .env("RUST_LOG", "info");

        if secure {
            builder.arg("-s");
        }

        let mut process = builder.spawn().unwrap();

        let stdout = process.stdout.take().unwrap();
        let mut stdout = BufReader::new(stdout).lines();

        for line in &mut stdout {
            let line = line.unwrap();
            if line.contains("echo service ready") {
                break;
            }
        }

        thread::spawn(move || {
            for line in stdout {
                let line = line.unwrap();
                println!("rama echo >> {}", line);
            }
        });

        Self { process }
    }

    /// Run any rama cmd
    pub(super) fn run(args: Vec<&'static str>) -> Result<String, Box<dyn std::error::Error>> {
        let child = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command()
            .stdout(std::process::Stdio::piped())
            .args(args)
            .env("RUST_LOG", "info")
            .spawn()
            .unwrap();

        let output = child.wait_with_output()?;
        assert!(output.status.success());
        let output = String::from_utf8(output.stdout)?;
        Ok(output)
    }

    /// Run the http command
    pub(super) fn http(
        input_args: Vec<&'static str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut args = vec!["http", "--debug", "-v", "--all", "-F", "-k"];
        args.extend(input_args);
        Self::run(args)
    }
}

impl Drop for RamaService {
    fn drop(&mut self) {
        self.process.kill().expect("kill server process");
    }
}
