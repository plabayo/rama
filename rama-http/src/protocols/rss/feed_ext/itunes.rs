//! iTunes podcast extension (<http://www.itunes.com/dtds/podcast-1.0.dtd>).

/// iTunes extension fields for a single podcast episode item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ITunes {
    pub title: Option<String>,
    pub author: Option<String>,
    pub subtitle: Option<String>,
    pub summary: Option<String>,
    pub image: Option<String>,
    pub duration: Option<String>,
    pub explicit: Option<bool>,
    pub episode: Option<u64>,
    pub season: Option<u64>,
    pub episode_type: Option<String>,
    pub block: Option<bool>,
    pub keywords: Option<String>,
}

/// iTunes extension fields at the feed (channel) level.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ITunesFeed {
    pub author: Option<String>,
    pub owner_name: Option<String>,
    pub owner_email: Option<String>,
    pub image: Option<String>,
    pub categories: Vec<String>,
    pub explicit: Option<bool>,
    pub type_: Option<String>,
    pub new_feed_url: Option<String>,
    pub block: Option<bool>,
    pub complete: Option<bool>,
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub summary: Option<String>,
}
