use rama_core::{Service, telemetry::tracing};
use rama_http_types::{
    HeaderValue, Request,
    header::{RAMA_ID_HEADER_VALUE, USER_AGENT},
};

#[derive(Debug, Clone)]
pub(crate) struct UserAgent<T> {
    inner: T,
    user_agent: HeaderValue,
}

impl<T> UserAgent<T> {
    pub(crate) fn new(inner: T, user_agent: Option<HeaderValue>) -> Self {
        let user_agent = user_agent
            .map(|value| {
                let mut buf = Vec::new();
                buf.extend(value.as_bytes());
                buf.push(b' ');
                buf.extend(RAMA_ID_HEADER_VALUE.as_bytes());
                HeaderValue::from_bytes(&buf).expect("user-agent should be valid")
            })
            .unwrap_or(RAMA_ID_HEADER_VALUE);

        Self { inner, user_agent }
    }
}

impl<T, ReqBody> Service<Request<ReqBody>> for UserAgent<T>
where
    T: Service<Request<ReqBody>>,
{
    type Output = T::Output;
    type Error = T::Error;

    fn serve(
        &self,
        mut req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        if let Ok(Some(user_agent)) = req
            .headers_mut()
            .try_insert(USER_AGENT, self.user_agent.clone())
        {
            // The User-Agent header has already been set on the request. Let's
            // append our user agent to the end.
            let mut buf = Vec::with_capacity(user_agent.len() + 1 + self.user_agent.len());
            buf.extend(user_agent.as_bytes());
            buf.push(b' ');
            buf.extend(self.user_agent.as_bytes());

            match HeaderValue::from_bytes(&buf) {
                Ok(value) => req.headers_mut().insert(USER_AGENT, value),
                Err(err) => tracing::debug!("failed to create new rama-grpc user agent: {err}"),
            }
        }

        self.inner.serve(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Svc;

    #[test]
    fn sets_default_if_no_custom_user_agent() {
        assert_eq!(
            UserAgent::new(Svc, None).user_agent,
            HeaderValue::from_static(RAMA_ID_HEADER_VALUE)
        )
    }

    #[test]
    fn prepends_custom_user_agent_to_default() {
        assert_eq!(
            UserAgent::new(Svc, Some(HeaderValue::from_static("Greeter 1.1"))).user_agent,
            HeaderValue::from_str(&format!(
                "Greeter 1.1 {}",
                RAMA_ID_HEADER_VALUE.to_str().unwrap()
            ))
            .unwrap()
        )
    }

    struct TestSvc {
        pub expected_user_agent: String,
    }

    impl Service<Request<()>> for TestSvc {
        type Output = ();
        type Error = ();

        async fn serve(&self, req: Request<()>) -> Result<Self::Output, Self::Error> {
            let user_agent = req.headers().get(USER_AGENT).unwrap().to_str().unwrap();
            assert_eq!(user_agent, self.expected_user_agent);
            Ok(())
        }
    }

    #[tokio::test]
    async fn sets_default_user_agent_if_none_present() {
        let expected_user_agent = RAMA_ID_HEADER_VALUE.to_string();
        let mut ua = UserAgent::new(
            TestSvc {
                expected_user_agent,
            },
            None,
        );
        let _ = ua.call(Request::default()).await;
    }

    #[tokio::test]
    async fn sets_custom_user_agent_if_none_present() {
        let expected_user_agent = format!("Greeter 1.1 {}", RAMA_ID_HEADER_VALUE.to_str().unwrap());
        let mut ua = UserAgent::new(
            TestSvc {
                expected_user_agent,
            },
            Some(HeaderValue::from_static("Greeter 1.1")),
        );
        let _ = ua.call(Request::default()).await;
    }

    #[tokio::test]
    async fn appends_default_user_agent_to_request_user_agent() {
        let mut req = Request::default();
        req.headers_mut()
            .insert(USER_AGENT, HeaderValue::from_static("request-ua/x.y"));

        let expected_user_agent =
            format!("request-ua/x.y {}", RAMA_ID_HEADER_VALUE.to_str().unwrap());
        let mut ua = UserAgent::new(
            TestSvc {
                expected_user_agent,
            },
            None,
        );
        let _ = ua.call(req).await;
    }

    #[tokio::test]
    async fn appends_custom_user_agent_to_request_user_agent() {
        let mut req = Request::default();
        req.headers_mut()
            .insert(USER_AGENT, HeaderValue::from_static("request-ua/x.y"));

        let expected_user_agent = format!(
            "request-ua/x.y Greeter 1.1 {}",
            RAMA_ID_HEADER_VALUE.to_str().unwrap()
        );
        let mut ua = UserAgent::new(
            TestSvc {
                expected_user_agent,
            },
            Some(HeaderValue::from_static("Greeter 1.1")),
        );
        let _ = ua.call(req).await;
    }
}
