// SPDX-License-Identifier: GPL-3.0-or-later
//! The control-plane route table.

/// One entry of the control-plane route table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// `POST /feedback`
    Feedback,
    /// `POST /pair-pin-start`
    PairPinStart,
    /// `POST /pair-setup-pin`
    PairSetupPin,
    /// `POST /pair-setup`
    PairSetup,
    /// `POST /pair-verify`
    PairVerify,
    /// `POST /fp-setup`
    FairPlaySetup,
    /// `POST /audioMode`
    AudioMode,
    /// `GET` whose URL contains `/info`
    Info,
    /// `OPTIONS`, any target
    Options,
    /// `SETUP`, any target
    Setup,
    /// `GET_PARAMETER`, any target
    GetParameter,
    /// `SET_PARAMETER`, any target
    SetParameter,
    /// `RECORD`, any target
    Record,
    /// `FLUSH`, any target
    Flush,
    /// `TEARDOWN`, any target
    Teardown,
    /// `POST /reverse`
    Reverse,
    /// `POST /play`
    Play,
    /// `POST /getProperty?...`
    GetProperty,
    /// `POST /scrub?...`
    Scrub,
    /// `POST /rate?...`
    Rate,
    /// `POST /stop`
    Stop,
    /// `POST /action`
    Action,
    /// `POST /fp-setup2`
    FairPlaySetup2,
    /// `GET /server-info`
    ServerInfo,
    /// `GET /playback-info`
    PlaybackInfo,
    /// `PUT /setProperty?...`
    SetProperty,
    /// HLS request: a `Host` header without `CSeq` and without
    /// `X-Apple-Session-ID`.
    Hls,
    /// `ANNOUNCE`, which the protocol does not dispatch at all.
    ///
    /// This crate keeps it as a documented extension so a session can be
    /// announced before `SETUP`; it is deliberately absent from
    /// [`PUBLIC_METHODS`](super::PUBLIC_METHODS) because the protocol never advertises it.
    Announce,
}

impl Route {
    /// Whether this layer answers the route itself.
    ///
    /// The routes it answers are `OPTIONS`, `RECORD`, `TEARDOWN` and `ANNOUNCE`.
    /// Every other route is offered to the connection's [`RouteHandler`](super::types::RouteHandler), because those
    /// routes carry the session's key material and stream requests, or act on the media
    /// session a handler owns; a connection without one, or a handler that declines, is
    /// answered `501 Not Implemented`.
    pub fn is_local(self) -> bool {
        matches!(
            self,
            Self::Options | Self::Record | Self::Teardown | Self::Announce
        )
    }
}
