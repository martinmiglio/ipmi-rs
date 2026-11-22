use crate::{
    connection::{
        IpmiConnection, LogicalUnit, NetFn, NotEnoughData, Request, RequestTargetAddress, Response,
    },
    IpmiError,
};
use std::{net::ToSocketAddrs, num::NonZeroU32, time::Duration};

mod socket;

mod v1_5;
pub use v1_5::{
    ActivationError as V1_5ActivationError, ReadError as V1_5ReadError,
    WriteError as V1_5WriteError,
};

mod v2_0;
pub use v2_0::{
    ActivationError as V2_0ActivationError, ReadError as V2_0ReadError,
    WriteError as V2_0WriteError, *,
};

pub use ipmi_rs_core::app::auth::{
    AuthenticationAlgorithm, ConfidentialityAlgorithm, IntegrityAlgorithm,
};

mod checksum;

mod header;
pub(crate) use header::*;

mod asf;
pub(crate) use asf::*;

mod internal;
use internal::{Active, RmcpWithState, Unbound};

#[derive(Debug)]
pub enum RmcpIpmiReceiveError {
    Io(std::io::Error),
    RmcpHeader(RmcpHeaderError),
    Session(UnwrapSessionError),
    NotIpmi,
    NotEnoughData,
    EmptyMessage,
    IpmbChecksumFailed,
}

#[derive(Debug)]
pub enum RmcpIpmiSendError {
    V1_5(V1_5WriteError),
    V2_0(V2_0WriteError),
}

impl From<V1_5WriteError> for RmcpIpmiSendError {
    fn from(value: V1_5WriteError) -> Self {
        Self::V1_5(value)
    }
}

impl From<V2_0WriteError> for RmcpIpmiSendError {
    fn from(value: V2_0WriteError) -> Self {
        Self::V2_0(value)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum UnwrapSessionError {
    V1_5(V1_5ReadError),
    V2_0(V2_0ReadError),
}

impl From<V1_5ReadError> for UnwrapSessionError {
    fn from(value: V1_5ReadError) -> Self {
        Self::V1_5(value)
    }
}

impl From<V2_0ReadError> for UnwrapSessionError {
    fn from(value: V2_0ReadError) -> Self {
        Self::V2_0(value)
    }
}

#[derive(Debug)]
pub enum RmcpIpmiError {
    NotActive,
    Receive(RmcpIpmiReceiveError),
    Send(RmcpIpmiSendError),
    /// The BMC rejected the `Close Session` command with this completion code.
    ///
    /// `0x87` (`Invalid Session ID`) is reported here as well: it can mean the
    /// session is already gone, or that the ID that was sent is wrong.
    CloseSessionRejected(u8),
    /// The response did not answer the request that was sent.
    UnexpectedResponse {
        netfn_sent: NetFn,
        netfn_recvd: NetFn,
        cmd_sent: u8,
        cmd_recvd: u8,
    },
}

impl From<RmcpIpmiReceiveError> for RmcpIpmiError {
    fn from(value: RmcpIpmiReceiveError) -> Self {
        Self::Receive(value)
    }
}

impl From<RmcpIpmiSendError> for RmcpIpmiError {
    fn from(value: RmcpIpmiSendError) -> Self {
        Self::Send(value)
    }
}

type CommandError<T> = IpmiError<RmcpIpmiError, T>;

#[derive(Debug)]
pub enum ActivationError {
    BindSocket(std::io::Error),
    PingSend(std::io::Error),
    PongReceive(std::io::Error),
    PongRead,
    /// The contacted host does not support IPMI over RMCP.
    IpmiNotSupported,
    NoSupportedIpmiLANVersions,
    GetChannelAuthenticationCapabilities(CommandError<NotEnoughData>),
    V1_5(V1_5ActivationError),
    V2_0(V2_0ActivationError),
    RmcpError(RmcpHeaderError),
}

impl From<V1_5ActivationError> for ActivationError {
    fn from(value: V1_5ActivationError) -> Self {
        Self::V1_5(value)
    }
}

impl From<V2_0ActivationError> for ActivationError {
    fn from(value: V2_0ActivationError) -> Self {
        Self::V2_0(value)
    }
}

#[derive(Debug)]
pub struct Rmcp {
    unbound_state: RmcpWithState<Unbound>,
    active_state: Option<RmcpWithState<Active>>,
}

impl Rmcp {
    pub fn new<R>(remote: R, timeout: Duration) -> Result<Self, std::io::Error>
    where
        R: ToSocketAddrs + std::fmt::Debug,
    {
        let unbound_state = RmcpWithState::new(remote, timeout)?;

        Ok(Self {
            unbound_state,
            active_state: None,
        })
    }

    pub fn inactive_clone(&self) -> Self {
        Self {
            unbound_state: self.unbound_state.clone(),
            active_state: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.active_state.is_some()
    }

    /// Activate this RMCP connection with the provided username and password.
    ///
    /// If `rmcp_plus` is `true`, upgrade the connection to an RMCP+ connection
    /// if the remote host supports it.
    ///
    /// An active session is closed first. A failure to close it is logged at
    /// the `warn` level and does not stop activation. Because the close waits
    /// for the BMC's response, re-activation can take up to the connection's
    /// read timeout when the BMC does not answer.
    ///
    /// Activation always requests Administrator as the maximum privilege level
    /// (hardcoded in `rmcp::internal`), regardless of the account used; the BMC
    /// caps this to the account's limit. The session itself starts at User
    /// level, so callers that need a higher level must send
    /// [`crate::app::auth::SetSessionPrivilegeLevel`] after activation.
    pub fn activate(
        &mut self,
        rmcp_plus: bool,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<(), ActivationError> {
        if self.is_active() {
            if let Err(error) = self.deactivate() {
                log::warn!("Failed to close the previous IPMI session: {error:?}");
            }
        }

        let inactive = self
            .unbound_state
            .bind()
            .map_err(ActivationError::BindSocket)?;

        let activated = inactive.activate(rmcp_plus, username, password)?;
        self.active_state = Some(activated);
        Ok(())
    }

    /// Close the active IPMI session so the BMC can release its slot.
    ///
    /// The connection is inactive afterwards, even when the BMC rejects the
    /// command or does not answer. Sessions are not closed from `Drop`; call
    /// this (or re-activate) to release the slot deterministically.
    ///
    /// # Errors
    ///
    /// Returns an error when no session is active, when the response does not
    /// match the request, or when the BMC rejects the close.
    pub fn deactivate(&mut self) -> Result<(), RmcpIpmiError> {
        let Some(mut active) = self.active_state.take() else {
            return Err(RmcpIpmiError::NotActive);
        };

        // `Active::V1_5` is only constructed after a successful activation, so
        // in practice it always carries a session ID. Handle the absence
        // gracefully anyway rather than sending an ID the BMC never assigned.
        let Some(session_id) = active.session_id() else {
            log::debug!("Not closing the IPMI session: the active state has no session ID");
            return Ok(());
        };

        let mut request = close_session_request(session_id);
        let response = active.send_recv(&mut request)?;

        check_close_response(&request, &response)?;
        log::debug!("Closed IPMI session {:#010x}", session_id.get());

        Ok(())
    }
}

/// The command number of the IPMI `Close Session` command in the App netfn.
const CLOSE_SESSION_CMD: u8 = 0x3C;

/// Build the IPMI `Close Session` request.
fn close_session_request(session_id: NonZeroU32) -> Request {
    Request::new(
        crate::connection::Message::new_request(
            NetFn::App,
            CLOSE_SESSION_CMD,
            session_id.get().to_le_bytes().to_vec(),
        ),
        RequestTargetAddress::Bmc(LogicalUnit::Zero),
    )
}

/// Check that `response` answers `request` and that the close was accepted.
fn check_close_response(request: &Request, response: &Response) -> Result<(), RmcpIpmiError> {
    if response.netfn() != request.netfn() || response.cmd() != request.cmd() {
        return Err(RmcpIpmiError::UnexpectedResponse {
            netfn_sent: request.netfn(),
            netfn_recvd: response.netfn(),
            cmd_sent: request.cmd(),
            cmd_recvd: response.cmd(),
        });
    }

    match response.cc() {
        0 => Ok(()),
        completion_code => Err(RmcpIpmiError::CloseSessionRejected(completion_code)),
    }
}

impl IpmiConnection for Rmcp {
    type SendError = RmcpIpmiError;

    type RecvError = RmcpIpmiError;

    type Error = RmcpIpmiError;

    fn send(&mut self, request: &mut crate::connection::Request) -> Result<(), Self::SendError> {
        let active = self.active_state.as_mut().ok_or(RmcpIpmiError::NotActive)?;
        active.send(request)
    }

    fn recv(&mut self) -> Result<crate::connection::Response, Self::RecvError> {
        let active = self.active_state.as_mut().ok_or(RmcpIpmiError::NotActive)?;
        active.recv().map_err(RmcpIpmiError::Receive)
    }

    fn send_recv(
        &mut self,
        request: &mut crate::connection::Request,
    ) -> Result<crate::connection::Response, Self::Error> {
        let active = self.active_state.as_mut().ok_or(RmcpIpmiError::NotActive)?;
        active.send_recv(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::Message;

    fn close_request() -> Request {
        close_session_request(NonZeroU32::new(1).expect("non-zero"))
    }

    fn close_response(cc: u8) -> Response {
        Response::new(
            Message::new_response(NetFn::App, CLOSE_SESSION_CMD, vec![cc]),
            0,
        )
        .expect("non-empty response")
    }

    #[test]
    fn close_session_request_encodes_netfn_command_and_session_id() {
        let session_id = NonZeroU32::new(0x0102_0304).expect("non-zero");
        let request = close_session_request(session_id);

        assert_eq!(request.netfn(), NetFn::App);
        assert_eq!(request.netfn_raw(), 0x06);
        assert_eq!(request.cmd(), CLOSE_SESSION_CMD);
        assert_eq!(request.data(), &[0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn deactivate_without_session_is_not_active() {
        // `Rmcp::new` only resolves the address; `deactivate` must return
        // before any socket is bound or any packet is sent.
        let mut rmcp =
            Rmcp::new("127.0.0.1:623", Duration::from_millis(10)).expect("resolve address");

        assert!(matches!(rmcp.deactivate(), Err(RmcpIpmiError::NotActive)));
        assert!(!rmcp.is_active());
    }

    #[test]
    fn check_close_response_accepts_success() {
        assert!(check_close_response(&close_request(), &close_response(0)).is_ok());
    }

    #[test]
    fn check_close_response_rejects_non_zero_completion_code() {
        assert!(matches!(
            check_close_response(&close_request(), &close_response(0x87)),
            Err(RmcpIpmiError::CloseSessionRejected(0x87))
        ));
    }

    #[test]
    fn check_close_response_rejects_wrong_netfn_or_command() {
        let wrong_netfn = Response::new(
            Message::new_response(NetFn::SensorEvent, CLOSE_SESSION_CMD, vec![0]),
            0,
        )
        .expect("non-empty response");
        assert!(matches!(
            check_close_response(&close_request(), &wrong_netfn),
            Err(RmcpIpmiError::UnexpectedResponse {
                netfn_sent: NetFn::App,
                netfn_recvd: NetFn::SensorEvent,
                cmd_sent: CLOSE_SESSION_CMD,
                cmd_recvd: CLOSE_SESSION_CMD,
            })
        ));

        let wrong_cmd = Response::new(
            Message::new_response(NetFn::App, CLOSE_SESSION_CMD + 1, vec![0]),
            0,
        )
        .expect("non-empty response");
        assert!(matches!(
            check_close_response(&close_request(), &wrong_cmd),
            Err(RmcpIpmiError::UnexpectedResponse {
                cmd_sent: CLOSE_SESSION_CMD,
                cmd_recvd,
                ..
            }) if cmd_recvd == CLOSE_SESSION_CMD + 1
        ));
    }
}
