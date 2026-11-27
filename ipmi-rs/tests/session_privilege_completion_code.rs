//! Completion codes that are specific to a command must reach the caller as
//! typed errors.

use ipmi_rs::app::auth::{PrivilegeLevel, SetSessionPrivilegeLevel, SetSessionPrivilegeLevelError};
use ipmi_rs::connection::{CompletionErrorCode, IpmiConnection, Message, NetFn, Request, Response};
use ipmi_rs::{Ipmi, IpmiError};

#[derive(Debug)]
struct FakeConnection;

#[derive(Debug)]
struct FakeError;

impl IpmiConnection for FakeConnection {
    type SendError = FakeError;

    type RecvError = FakeError;

    type Error = FakeError;

    fn send(&mut self, _request: &mut Request) -> Result<(), Self::SendError> {
        Ok(())
    }

    fn recv(&mut self) -> Result<Response, Self::RecvError> {
        unreachable!("the test uses send_recv")
    }

    fn send_recv(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        // The BMC refused to raise the privilege level above the account limit.
        let message = Message::new_response(NetFn::App, request.cmd(), vec![0x81]);

        Ok(Response::new(message, 0).expect("the completion code is present"))
    }
}

#[test]
fn command_specific_completion_code_is_returned_to_the_caller() {
    let mut ipmi = Ipmi::new(FakeConnection);

    let error = ipmi
        .send_recv(SetSessionPrivilegeLevel {
            privilege_level: PrivilegeLevel::Administrator,
        })
        .unwrap_err();

    match error {
        IpmiError::Command {
            error,
            completion_code,
            ..
        } => {
            assert_eq!(error, SetSessionPrivilegeLevelError::ExceedsPrivilegeLimit);
            assert_eq!(
                completion_code,
                Some(CompletionErrorCode::CommandSpecific(0x81))
            );
        }
        other => panic!("expected a command error, got {other:?}"),
    }
}
