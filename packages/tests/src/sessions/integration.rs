use smart_account_auth::messages::{AllowedActions, CreateSession, SessionInfo};

use crate::types::ExecuteMsg;


#[test]
fn session_actions_simple() {
    let _create_msg = ExecuteMsg::CreateSession(CreateSession {
        allowed_actions: AllowedActions::All {},
        session_info: SessionInfo::default(),
    });

}







