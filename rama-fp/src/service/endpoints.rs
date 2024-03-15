use super::State;
use rama::{http::Request, service::Context};

type Html = rama::http::response::Html<String>;

fn html<T: Into<String>>(inner: T) -> Html {
    inner.into().into()
}

pub async fn get_root(_ctx: Context<State>, _req: Request) -> Html {
    html("<h1>Welcome to rama-fp</h1>")
}
