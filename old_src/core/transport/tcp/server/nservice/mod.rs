mod connection;
pub use connection::Connection;

pub trait Service<State> {
    type Error;
    type Output;

    async fn call(self, conn: Connection<State>) -> Result<Self::Output, Self::Error>;
}
