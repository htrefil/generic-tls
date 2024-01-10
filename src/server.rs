use crate::stream::Stream;

use rustls_pemfile::Item;
use std::future::{Future, Ready};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{future, io, iter, mem};
use thiserror::Error;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::{self, Certificate, PrivateKey, ServerConfig};
use tokio_rustls::server::TlsStream;
use tokio_rustls::{Accept, TlsAcceptor};

pub trait Acceptor: Clone + Sync + Send + Unpin + 'static {
    type Stream<T: Stream>: Stream;
    type Accept<T: Stream>: Future<Output = Result<Self::Stream<T>, io::Error>> + Unpin;

    fn accept<T: Stream>(&self, stream: T) -> Self::Accept<T>;
}

impl Acceptor for TlsAcceptor {
    type Stream<T: Stream> = TlsStream<T>;
    type Accept<T: Stream> = Accept<T>;

    fn accept<T: Stream>(&self, stream: T) -> Self::Accept<T> {
        TlsAcceptor::accept(self, stream)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RawAcceptor;

impl Acceptor for RawAcceptor {
    type Stream<T: Stream> = T;
    type Accept<T: Stream> = Ready<Result<T, io::Error>>;

    fn accept<T: Stream>(&self, stream: T) -> Self::Accept<T> {
        future::ready(Ok(stream))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MaybeAcceptor<T>(pub Option<T>);

impl<T: Acceptor> Acceptor for MaybeAcceptor<T> {
    type Stream<U: Stream> = MaybeStream<T::Stream<U>, U>;
    type Accept<U: Stream> = MaybeAccept<T, U>;

    fn accept<U: Stream>(&self, stream: U) -> Self::Accept<U> {
        match &self.0 {
            Some(acceptor) => MaybeAccept::Tls(acceptor.accept(stream)),
            None => MaybeAccept::Raw(stream),
        }
    }
}

pub enum MaybeStream<T, U> {
    Tls(T),
    Raw(U),
}

impl<T: AsyncRead + Unpin, U: AsyncRead + Unpin> AsyncRead for MaybeStream<T, U> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Tls(tls) => Pin::new(tls).poll_read(context, buffer),
            Self::Raw(raw) => Pin::new(raw).poll_read(context, buffer),
        }
    }
}

impl<T: AsyncWrite + Unpin, U: AsyncWrite + Unpin> AsyncWrite for MaybeStream<T, U> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Self::Tls(tls) => Pin::new(tls).poll_write(context, data),
            Self::Raw(raw) => Pin::new(raw).poll_write(context, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Tls(tls) => Pin::new(tls).poll_flush(context),
            Self::Raw(raw) => Pin::new(raw).poll_flush(context),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Tls(tls) => Pin::new(tls).poll_shutdown(context),
            Self::Raw(raw) => Pin::new(raw).poll_shutdown(context),
        }
    }
}

pub enum MaybeAccept<T: Acceptor, U: Stream> {
    Tls(T::Accept<U>),
    Raw(U),
    Done,
}

impl<T: Acceptor, U: Stream> Future for MaybeAccept<T, U> {
    type Output = Result<MaybeStream<T::Stream<U>, U>, io::Error>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match mem::replace(this, Self::Done) {
            Self::Tls(mut tls) => match Pin::new(&mut tls).poll(context) {
                Poll::Ready(tls) => Poll::Ready(tls.map(MaybeStream::Tls)),
                Poll::Pending => {
                    *this = Self::Tls(tls);
                    Poll::Pending
                }
            },
            Self::Raw(raw) => Poll::Ready(Ok(MaybeStream::Raw(raw))),
            Self::Done => panic!("MaybeAccept already polled to completion"),
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("Multiple private keys provided")]
    MultipleKeys,
    #[error("No suitable private keys provided")]
    NoKeys,
}

pub async fn configure(certificate: &Path, key: &Path) -> Result<TlsAcceptor, Error> {
    enum LoadedItem {
        Certificate(Vec<u8>),
        Key(Vec<u8>),
    }

    let certificate = fs::read_to_string(certificate).await?;
    let key = fs::read_to_string(key).await?;

    let certificates_iter = iter::from_fn({
        let mut buffer = certificate.as_bytes();

        move || rustls_pemfile::read_one(&mut buffer).transpose()
    })
    .filter_map(|item| match item {
        Ok(Item::X509Certificate(data)) => Some(Ok(LoadedItem::Certificate(data))),
        Err(err) => Some(Err(err)),
        _ => None,
    });

    let keys_iter = iter::from_fn({
        let mut buffer = key.as_bytes();

        move || rustls_pemfile::read_one(&mut buffer).transpose()
    })
    .filter_map(|item| match item {
        Ok(Item::RSAKey(data)) | Ok(Item::PKCS8Key(data)) | Ok(Item::ECKey(data)) => {
            Some(Ok(LoadedItem::Key(data)))
        }
        Err(err) => Some(Err(err)),
        _ => None,
    });

    let mut certificates = Vec::new();
    let mut key = None;

    for item in certificates_iter.chain(keys_iter) {
        let item = item?;

        match item {
            LoadedItem::Certificate(data) => certificates.push(Certificate(data)),
            LoadedItem::Key(data) => {
                if key.is_some() {
                    return Err(Error::MultipleKeys);
                }

                key = Some(PrivateKey(data));
            }
        }
    }

    let key = key.ok_or(Error::NoKeys)?;

    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map(Arc::new)
        .map(Into::into)
        .map_err(Into::into)
}
