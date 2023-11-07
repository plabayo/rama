use http::{
    header::{AsHeaderName, GetAll},
    HeaderValue, Request, Response,
};

pub trait HeaderValueGetter {
    fn header_value<K>(&self, key: K) -> Option<&HeaderValue>
    where
        K: AsHeaderName;
    fn header_values<K>(&self, key: K) -> GetAll<'_, HeaderValue>
    where
        K: AsHeaderName;
}

impl<Body> HeaderValueGetter for Request<Body> {
    fn header_value<K>(&self, key: K) -> Option<&HeaderValue>
    where
        K: AsHeaderName,
    {
        self.headers().get(key)
    }

    fn header_values<K>(&self, key: K) -> GetAll<'_, HeaderValue>
    where
        K: AsHeaderName,
    {
        self.headers().get_all(key)
    }
}

impl<Body> HeaderValueGetter for Response<Body> {
    fn header_value<K>(&self, key: K) -> Option<&HeaderValue>
    where
        K: AsHeaderName,
    {
        self.headers().get(key)
    }

    fn header_values<K>(&self, key: K) -> GetAll<'_, HeaderValue>
    where
        K: AsHeaderName,
    {
        self.headers().get_all(key)
    }
}
