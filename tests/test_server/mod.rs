
use std::process::Child;

pub struct ExampleServer(Child);

impl std::ops::Drop for ExampleServer {
    fn drop(&mut self) {
        let Ok(_) = self.0.kill()else{
            println!("faild kill a process. ");
            return;
        };
    }
}

pub fn run_example_server(example_name: &str, port_number: usize) -> ExampleServer {
    let temp = assert_fs::TempDir::new().unwrap();
    ExampleServer(
        escargot::CargoBuild::new()
            .example(example_name)
            .manifest_path("Cargo.toml")
            .target_dir(temp.path())
            .run()
            .unwrap()
            .command()
            .arg(port_number.to_string())
            .spawn()
            .unwrap(),
    )
}
