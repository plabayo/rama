use std::io::{Error as IoError, ErrorKind};

use rama::http::headers::{RetryAfter, util::Seconds};
use tokio::sync::OwnedSemaphorePermit;

use super::*;

mod profiles;

impl DashboardState {
    fn acquire_export_permit(&self) -> Result<Option<OwnedSemaphorePermit>, BoxError> {
        self.export_limit
            .as_ref()
            .map(|limit| {
                limit.clone().try_acquire_owned().map_err(|_full| {
                    IoError::new(
                        ErrorKind::WouldBlock,
                        "too many inspector exports are already in progress",
                    )
                    .into()
                })
            })
            .transpose()
    }
}

fn export_busy(error: BoxError) -> Response {
    (
        Headers::single(RetryAfter::delay(Seconds::new(1))),
        error_response(StatusCode::TOO_MANY_REQUESTS, error),
    )
        .into_response()
}

pub(super) async fn export_profiles(
    State(state): State<DashboardState>,
    Query(query): Query<ExportQuery>,
) -> Response {
    let (request_ids, connection_ids) = match export_selection(&state, query) {
        Ok(selection) => selection,
        Err(status) => return status.into_response(),
    };
    let permit = match state.acquire_export_permit() {
        Ok(permit) => permit,
        Err(error) => return export_busy(error),
    };
    match profiles::download(&state.capture, &request_ids, &connection_ids, permit).await {
        Ok(download) => download.into_response(),
        Err(error) => {
            let status = match error.downcast_ref::<IoError>().map(IoError::kind) {
                Some(ErrorKind::InvalidInput) => StatusCode::UNPROCESSABLE_ENTITY,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            error_response(status, error)
        }
    }
}

pub(super) async fn export_har(
    State(state): State<DashboardState>,
    Query(query): Query<ExportQuery>,
) -> Response {
    let (request_ids, connection_ids) = match export_selection(&state, query) {
        Ok(selection) => selection,
        Err(status) => return status.into_response(),
    };
    let permit = match state.acquire_export_permit() {
        Ok(permit) => permit,
        Err(error) => return export_busy(error),
    };
    match export_selected(&state.capture, &request_ids, &connection_ids, permit).await {
        Ok(download) => har_download_response(download),
        Err(error) => error_response(StatusCode::BAD_REQUEST, error),
    }
}

pub(super) fn export_selection(
    state: &DashboardState,
    query: ExportQuery,
) -> Result<(BTreeSet<u64>, BTreeSet<u64>), StatusCode> {
    if query.ids.is_some() || query.connection_ids.is_some() {
        return Ok((
            parse_export_ids(query.ids.as_deref()),
            parse_export_ids(query.connection_ids.as_deref()),
        ));
    }
    let Some(session_id) = query.session else {
        return Ok((BTreeSet::new(), BTreeSet::new()));
    };
    if !state.has_session(&session_id) {
        return Err(StatusCode::NOT_FOUND);
    }
    let session = state.session(&session_id);
    Ok((session.selected, session.selected_connections))
}

pub(super) fn parse_export_ids(ids: Option<&str>) -> BTreeSet<u64> {
    ids.into_iter()
        .flat_map(|ids| ids.split(','))
        .filter_map(|id| id.trim().parse().ok())
        .collect()
}

pub(super) async fn start_har(
    State(state): State<DashboardState>,
    Query(query): Query<StartHarQuery>,
) -> Response {
    if query
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let _transition = state.recording_transition.lock().await;
    if !state.inspection.is_enabled() {
        return error_response(
            StatusCode::CONFLICT,
            "Resume inspector before starting a HAR recording",
        );
    }
    match state.har.start_browser(query.file_name).await {
        Ok(_) => {
            state.notify();
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => error_response(StatusCode::BAD_REQUEST, error),
    }
}

pub(super) async fn stop_har(
    State(state): State<DashboardState>,
    Query(query): Query<HarSessionQuery>,
) -> Response {
    if query
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = state.har.stop_browser().await;
    state.notify();
    match result {
        Ok(download) => har_download_response(download),
        Err(error) => error_response(StatusCode::BAD_REQUEST, error),
    }
}

pub(super) fn har_download_response(download: HarDownload) -> Response {
    (
        Headers((
            ContentType::json(),
            ContentLength(download.content_length),
            CacheControl::new().with_no_store(),
            ContentDisposition::attachment(&download.file_name),
        )),
        Body::from_stream(ReaderStream::new(download.reader)),
    )
        .into_response()
}
