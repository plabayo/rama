#[derive(Clone, PartialEq, prost::Message)]
pub struct KeyValue {
    #[prost(string)]
    pub key: String,

    #[prost(string)]
    pub value: String,
}
