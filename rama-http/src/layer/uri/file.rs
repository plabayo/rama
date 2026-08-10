//! Serve `file://` request URIs from the local filesystem.
//!
//! A client stack layered with [`FileUriLayer`] answers `file://` requests
//! itself and passes every other scheme to the inner service, so one client
//! serves both local and remote URIs.
//!
//! Place this layer *outside* any
//! [`FollowRedirectLayer`][crate::layer::follow_redirect::FollowRedirectLayer]:
//! redirects are followed by the inner service, so a remote response can never
//! redirect into the local filesystem.
//!
//! This is a **client-side** layer: the request target is your own. Mounting
//! it in a server stack, where the request target is attacker-controlled,
//! turns any absolute-form `file://` target into an arbitrary local-file read.
//! If you must, always confine it with [`FileUriLayer::with_jail`]; the
//! default (`None`) serves any readable absolute path.

use std::path::{Path, PathBuf};

use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt, ErrorContext, ErrorExt},
};
use rama_net::{Protocol, uri::file_uri_path};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};

use crate::{
    Body, Method, Request, Response, StatusCode,
    headers::{ContentType, HttpResponseBuilderExt as _},
    mime::{Mime, guess as mime_guess},
};

/// Serve `file://` request URIs from the local filesystem.
///
/// See the [module docs](crate::layer::uri::file) for an example.
#[derive(Debug, Clone, Default)]
pub struct FileUriLayer {
    jail: Option<PathBuf>,
}

impl FileUriLayer {
    /// Create a new [`FileUriLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Confine served files to within this root directory,
        /// rejecting any path resolving outside it.
        pub fn jail(mut self, jail: Option<PathBuf>) -> Self {
            self.jail = jail;
            self
        }
    }
}

impl<S> Layer<S> for FileUriLayer {
    type Service = FileUriService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        FileUriService {
            inner,
            jail: self.jail.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        FileUriService {
            inner,
            jail: self.jail,
        }
    }
}

/// Serve `file://` request URIs from the local filesystem.
///
/// See the [module docs](crate::layer::uri::file) for an example.
#[derive(Debug, Clone)]
pub struct FileUriService<S> {
    inner: S,
    jail: Option<PathBuf>,
}

impl<S> FileUriService<S> {
    /// Create a new [`FileUriService`].
    pub const fn new(inner: S) -> Self {
        Self { inner, jail: None }
    }

    generate_set_and_with! {
        /// Confine served files to within this root directory,
        /// rejecting any path resolving outside it.
        pub fn jail(mut self, jail: Option<PathBuf>) -> Self {
            self.jail = jail;
            self
        }
    }

    define_inner_service_accessors!();
}

impl<S, ReqBody> Service<Request<ReqBody>> for FileUriService<S>
where
    S: Service<Request<ReqBody>, Output = Response, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        if req.uri().scheme() != Some(&Protocol::FILE) {
            return self.inner.serve(req).await.map_err(Into::into);
        }

        if !matches!(req.method(), &Method::GET | &Method::HEAD) {
            return Err(BoxError::from_static_str(
                "file:// URIs support GET and HEAD only",
            ));
        }

        // canonicalize resolves `.`/`..` (incl. percent-encoded) and clamps to
        // root before touching the fs; safe_open is the traversal backstop
        let uri = req.uri().clone().canonicalize();
        let path = file_uri_path(&uri).context("resolve file: uri path")?;

        let file = match &self.jail {
            Some(root) => rama_utils::fs::safe_open_under(root, &path).await,
            None => rama_utils::fs::safe_open(&path).await,
        }
        .context("open file")
        .with_context_str_field("path", || path.to_string_lossy())?;

        // stat the open handle rather than the path: a directory opens fine on
        // unix and would otherwise only fail once the body is read, long after
        // the 200 OK and its headers were committed
        let metadata = file
            .metadata()
            .await
            .context("stat file")
            .with_context_str_field("path", || path.to_string_lossy())?;
        if !metadata.is_file() {
            return Err(
                BoxError::from_static_str("file: uri does not point to a regular file")
                    .context_str_field("path", path.to_string_lossy()),
            );
        }

        let body = if req.method() == Method::HEAD {
            Body::empty()
        } else {
            Body::from_stream(rama_core::stream::io::ReaderStream::new(file))
        };
        Response::builder()
            .status(StatusCode::OK)
            .typed_header(ContentType::new(guess_mime(&path)))
            .body(body)
            .context("build file:// response")
    }
}

/// Guess the media type from the file extension, mirroring
/// [`ServeFile`][crate::service::fs::ServeFile].
fn guess_mime(path: &Path) -> Mime {
    mime_guess::from_path(path)
        .first()
        .unwrap_or(crate::mime::APPLICATION_OCTET_STREAM)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use rama_core::service::service_fn;

    use super::*;
    use crate::{BodyExtractExt as _, headers::HeaderMapExt as _};
    use rama_net::uri::Uri;

    fn service() -> FileUriService<impl Service<Request, Output = Response, Error = Infallible>> {
        FileUriService::new(service_fn(async |_: Request| {
            Ok::<_, Infallible>(Response::new(Body::from("remote")))
        }))
    }

    /// `file://` uri for a local path. Windows paths are neither rooted nor
    /// `/`-separated, so they need rewriting to be uri syntax at all.
    fn file_uri(path: &Path) -> String {
        let path = path.display().to_string().replace('\\', "/");
        if path.starts_with('/') {
            format!("file://{path}")
        } else {
            format!("file:///{path}")
        }
    }

    /// A directory is refused either by the metadata check (unix opens a
    /// directory fine) or by the open itself (windows does not).
    #[track_caller]
    fn assert_not_a_regular_file(err: &BoxError, ctx: &str) {
        let err = err.to_string();
        let refused = if cfg!(unix) {
            err.contains("regular file")
        } else {
            err.contains("regular file") || err.contains("open file")
        };
        assert!(refused, "{ctx}: unexpected error: {err}");
    }

    async fn get(
        svc: &impl Service<Request, Output = Response, Error = BoxError>,
        uri: &str,
    ) -> Result<Response, BoxError> {
        let uri: Uri = uri.parse().unwrap();
        svc.serve(Request::get(uri).body(Body::empty()).unwrap())
            .await
    }

    #[test]
    fn file_uri_of_a_windows_shaped_path_is_parseable() {
        let raw = file_uri(Path::new(r"C:\Users\rama\Temp\pac.js"));
        assert_eq!(raw, "file:///C:/Users/rama/Temp/pac.js");
        let uri: Uri = raw.parse().unwrap();
        assert_eq!(uri.scheme(), Some(&Protocol::FILE));

        assert_eq!(file_uri(Path::new("/tmp/pac.js")), "file:///tmp/pac.js");
    }

    #[tokio::test]
    async fn non_file_scheme_passes_through() {
        let resp = get(&service(), "http://example.com/x").await.unwrap();
        assert_eq!(resp.try_into_string().await.unwrap(), "remote");
    }

    #[tokio::test]
    async fn serves_local_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pac.js"), "DIRECT").unwrap();
        let uri = format!("{}/pac.js", file_uri(dir.path()));

        let resp = get(&service(), &uri).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .typed_get::<ContentType>()
                .unwrap()
                .into_mime(),
            crate::mime::TEXT_JAVASCRIPT,
        );
        assert_eq!(resp.try_into_string().await.unwrap(), "DIRECT");
    }

    #[tokio::test]
    async fn unknown_extension_falls_back_to_octet_stream() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pac.unknownext"), "DIRECT").unwrap();
        let uri = format!("{}/pac.unknownext", file_uri(dir.path()));

        let resp = get(&service(), &uri).await.unwrap();
        assert_eq!(
            resp.headers()
                .typed_get::<ContentType>()
                .unwrap()
                .into_mime(),
            crate::mime::APPLICATION_OCTET_STREAM,
        );
    }

    #[tokio::test]
    async fn head_has_no_body() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pac.js"), "DIRECT").unwrap();
        let uri = format!("{}/pac.js", file_uri(dir.path()));

        let resp = service()
            .serve(
                Request::builder()
                    .method(Method::HEAD)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.try_into_string().await.unwrap(), "");
    }

    #[tokio::test]
    async fn rejects_non_get_methods() {
        let err = service()
            .serve(
                Request::builder()
                    .method(Method::POST)
                    .uri("file:///tmp/x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("GET and HEAD"), "{err}");
    }

    #[tokio::test]
    async fn missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let uri = format!("{}/nope.js", file_uri(dir.path()));
        let err = get(&service(), &uri).await.unwrap_err().to_string();

        // the path rides along as a structured field, never formatted into
        // the error's own message
        assert!(err.contains("open file"), "{err}");
        assert!(err.contains("path="), "{err}");
        assert!(err.contains("nope.js"), "{err}");
    }

    #[tokio::test]
    async fn directory_is_not_served() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();

        for uri in [
            file_uri(dir.path()),
            format!("{}/", file_uri(dir.path())),
            format!("{}/sub", file_uri(dir.path())),
        ] {
            let err = get(&service(), &uri).await.unwrap_err();
            assert_not_a_regular_file(&err, &uri);
        }

        // a jail root is a directory too, and must not be served as its own file
        let svc = service().with_jail(dir.path().to_path_buf());
        let uri = file_uri(dir.path());
        let err = get(&svc, &uri).await.unwrap_err();
        assert_not_a_regular_file(&err, &uri);

        // ... while a regular file in the same directory still is
        std::fs::write(dir.path().join("pac.js"), "DIRECT").unwrap();
        let uri = format!("{}/pac.js", file_uri(dir.path()));
        let resp = get(&service(), &uri).await.unwrap();
        assert_eq!(resp.try_into_string().await.unwrap(), "DIRECT");
    }

    #[tokio::test]
    async fn head_of_a_directory_is_not_a_success() {
        let dir = tempfile::tempdir().unwrap();
        let uri = format!("{}/", file_uri(dir.path()));
        let err = service()
            .serve(
                Request::builder()
                    .method(Method::HEAD)
                    .uri(uri.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap_err();
        assert_not_a_regular_file(&err, &uri);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_to_directory_is_not_served() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("sub"), dir.path().join("link")).unwrap();

        let uri = format!("{}/link", file_uri(dir.path()));
        let err = get(&service(), &uri).await.unwrap_err();
        assert_not_a_regular_file(&err, &uri);
    }

    /// RFC 8089 no-authority form; the path shape is unix-specific.
    #[cfg(unix)]
    #[tokio::test]
    async fn no_authority_form_with_dot_segments_is_served() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pac.js"), "DIRECT").unwrap();

        let uri = format!("file:{}/sub/../pac.js", dir.path().display());
        let resp = get(&service(), &uri).await.unwrap();
        assert_eq!(resp.try_into_string().await.unwrap(), "DIRECT");
    }

    #[tokio::test]
    async fn jail_rejects_paths_outside_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "leak").unwrap();
        std::fs::write(root.path().join("ok"), "fine").unwrap();

        let svc = service().with_jail(root.path().to_path_buf());
        let uri = format!("{}/secret", file_uri(outside.path()));
        let _err = get(&svc, &uri).await.unwrap_err();

        let uri = format!("{}/ok", file_uri(root.path()));
        let resp = get(&svc, &uri).await.unwrap();
        assert_eq!(resp.try_into_string().await.unwrap(), "fine");
    }

    #[tokio::test]
    async fn redirect_into_file_scheme_is_not_served() {
        use crate::layer::follow_redirect::FollowRedirectLayer;
        use crate::{StatusCode, header::LOCATION};
        use rama_core::Layer as _;

        // layered outside the redirect follower: the redirect is resolved by
        // the inner service, so its file:// location never reaches this layer
        let svc = (FileUriLayer::new(), FollowRedirectLayer::new()).into_layer(service_fn(
            async |req: Request| {
                Ok::<_, Infallible>(if req.uri().scheme() == Some(&Protocol::FILE) {
                    Response::new(Body::from("inner saw file scheme"))
                } else {
                    Response::builder()
                        .status(StatusCode::FOUND)
                        .header(LOCATION, "file:///etc/hosts")
                        .body(Body::empty())
                        .unwrap()
                })
            },
        ));

        let resp = get(&svc, "http://example.com/redirect").await.unwrap();
        assert_eq!(
            resp.try_into_string().await.unwrap(),
            "inner saw file scheme"
        );
    }

    #[tokio::test]
    async fn traversal_is_clamped_to_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pac.js"), "DIRECT").unwrap();
        // `..` segments are resolved before the fs is touched
        let uri = format!("{}/sub/../pac.js", file_uri(dir.path()));

        let resp = get(&service(), &uri).await.unwrap();
        assert_eq!(resp.try_into_string().await.unwrap(), "DIRECT");
    }
}
