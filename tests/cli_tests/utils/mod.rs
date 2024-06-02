#![allow(dead_code)]

use std::{
    io::{BufRead, BufReader},
    process::Child,
    thread,
};

#[derive(Debug)]
/// A wrapper around a rama service process.
pub struct RamaService {
    process: Child,
}

impl RamaService {
    /// Start the rama Ip service with the given port.
    pub fn ip(port: u16) -> Self {
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
    pub fn echo(port: u16) -> Self {
        let mut process = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command()
            .stdout(std::process::Stdio::piped())
            .arg("echo")
            .arg("-p")
            .arg(port.to_string())
            .spawn()
            .unwrap();

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
    pub fn run(args: Vec<&'static str>) -> Result<String, Box<dyn std::error::Error>> {
        let child = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command()
            .stdout(std::process::Stdio::piped())
            .args(args)
            .spawn()
            .unwrap();

        let output = child.wait_with_output()?;
        assert!(output.status.success());
        let output = String::from_utf8(output.stdout)?;
        Ok(output)
    }

    /// Run the http command
    pub fn http(input_args: Vec<&'static str>) -> Result<String, Box<dyn std::error::Error>> {
        let mut args = vec!["http", "--debug", "-v", "--all", "-F"];
        args.extend(input_args);
        Self::run(args)
    }
}

impl Drop for RamaService {
    fn drop(&mut self) {
        self.process.kill().expect("kill server process");
    }
}
