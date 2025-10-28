use groups_relay::{
    Groups, StoreCommand, KIND_GROUP_ADD_USER_9000, KIND_GROUP_CREATE_9007,
    KIND_GROUP_CREATE_INVITE_9009, KIND_GROUP_USER_JOIN_REQUEST_9021,
};
use nostr_lmdb::Scope;
use nostr_sdk::prelude::*;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;

async fn create_test_keys() -> (Keys, Keys, Keys) {
    (Keys::generate(), Keys::generate(), Keys::generate())
}

async fn create_test_event(keys: &Keys, kind: Kind, tags: Vec<Tag>) -> Box<Event> {
    let unsigned_event = EventBuilder::new(kind, "")
        .tags(tags)
        .build_with_ctx(&Instant::now(), keys.public_key());
    let event = keys.sign_event(unsigned_event).await.unwrap();
    Box::new(event)
}

async fn create_test_groups_with_db(admin_keys: &Keys) -> Groups {
    let temp_dir = TempDir::new().unwrap();
    let db = relay_builder::RelayDatabase::new(
        temp_dir
            .path()
            .join("test.db")
            .to_string_lossy()
            .to_string(),
    )
    .unwrap();

    std::mem::forget(temp_dir);

    Groups::load_groups(
        Arc::new(db),
        admin_keys.public_key(),
        "wss://test.relay.url".to_string(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn test_preauth_invite_creation_and_usage() {
    let (admin_keys, user_keys, _) = create_test_keys().await;
    let groups = create_test_groups_with_db(&admin_keys).await;
    let scope = Scope::Default;
    let group_id = "test_preauth_group";

    // Create group
    let create_event = create_test_event(
        &admin_keys,
        KIND_GROUP_CREATE_9007,
        vec![Tag::custom(TagKind::h(), vec![group_id])],
    )
    .await;
    groups
        .handle_group_create(create_event, &scope)
        .await
        .unwrap();

    // Create preauth invite with expiration
    let preauth_code = "preauth123";
    let expires_at = (Timestamp::now().as_u64() + 3600).to_string(); // 1 hour from now
    let invite_tags = vec![
        Tag::custom(TagKind::h(), vec![group_id]),
        Tag::custom(TagKind::custom("code"), vec![preauth_code]),
        Tag::custom(TagKind::custom("preauth"), Vec::<String>::new()),
        Tag::custom(TagKind::custom("expires"), vec![expires_at]),
    ];
    let invite_event =
        create_test_event(&admin_keys, KIND_GROUP_CREATE_INVITE_9009, invite_tags).await;

    let result = groups.handle_create_invite(invite_event, &scope);
    assert!(result.is_ok());

    // Verify preauth invite was created
    {
        let group = groups.get_group(&scope, group_id).unwrap();
        let invite = group.value().invites.get(preauth_code).unwrap();
        assert!(invite.is_preauth);
        assert!(invite.expires_at.is_some());
        assert!(invite.can_use());
    }

    // User joins with preauth code
    let join_tags = vec![
        Tag::custom(TagKind::h(), vec![group_id]),
        Tag::custom(TagKind::custom("code"), vec![preauth_code]),
    ];
    let join_event =
        create_test_event(&user_keys, KIND_GROUP_USER_JOIN_REQUEST_9021, join_tags).await;

    let commands = groups.handle_join_request(join_event, &scope).unwrap();

    // Verify we got the expected commands for preauth auto-approval
    assert!(
        commands.len() >= 2,
        "Should have at least 2 commands (join request + add-user event)"
    );

    // Check that we have a Kind 9000 add-user event in the commands
    let has_add_user_event = commands.iter().any(|cmd| match cmd {
        StoreCommand::SaveUnsignedEvent(event, _, _) => event.kind == KIND_GROUP_ADD_USER_9000,
        _ => false,
    });
    assert!(
        has_add_user_event,
        "Should generate a Kind 9000 add-user event for preauth approval"
    );

    // Verify user was added to the group
    {
        let group = groups.get_group(&scope, group_id).unwrap();
        assert!(group.value().is_member(&user_keys.public_key()));
        assert!(!group
            .value()
            .join_requests
            .contains(&user_keys.public_key()));

        // Verify preauth code was marked as used
        let invite = group.value().invites.get(preauth_code).unwrap();
        assert!(!invite.can_use()); // Should be marked as used
    }
}

#[tokio::test]
async fn test_preauth_invite_expiration() {
    let (admin_keys, user_keys, _) = create_test_keys().await;
    let groups = create_test_groups_with_db(&admin_keys).await;
    let scope = Scope::Default;
    let group_id = "test_expired_preauth_group";

    // Create group
    let create_event = create_test_event(
        &admin_keys,
        KIND_GROUP_CREATE_9007,
        vec![Tag::custom(TagKind::h(), vec![group_id])],
    )
    .await;
    groups
        .handle_group_create(create_event, &scope)
        .await
        .unwrap();

    // Create a valid preauth invite that will expire later
    let preauth_code = "expiring_preauth123";
    let expires_at = (Timestamp::now().as_u64() + 1).to_string(); // Expires in 1 second
    let invite_tags = vec![
        Tag::custom(TagKind::h(), vec![group_id]),
        Tag::custom(TagKind::custom("code"), vec![preauth_code]),
        Tag::custom(TagKind::custom("preauth"), Vec::<String>::new()),
        Tag::custom(TagKind::custom("expires"), vec![expires_at]),
    ];
    let invite_event =
        create_test_event(&admin_keys, KIND_GROUP_CREATE_INVITE_9009, invite_tags).await;

    groups.handle_create_invite(invite_event, &scope).unwrap();

    // Verify preauth invite was created
    {
        let group = groups.get_group(&scope, group_id).unwrap();
        let invite = group.value().invites.get(preauth_code).unwrap();
        assert!(invite.is_preauth);
        assert!(!invite.is_expired()); // Should not be expired yet
        assert!(invite.can_use());
    }

    // Wait for expiration + small buffer
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Now the invite should be expired
    {
        let group = groups.get_group(&scope, group_id).unwrap();
        let invite = group.value().invites.get(preauth_code).unwrap();
        assert!(invite.is_preauth);
        assert!(invite.is_expired());
        assert!(!invite.can_use());
    }

    // User tries to join with now-expired preauth code
    let join_tags = vec![
        Tag::custom(TagKind::h(), vec![group_id]),
        Tag::custom(TagKind::custom("code"), vec![preauth_code]),
    ];
    let join_event =
        create_test_event(&user_keys, KIND_GROUP_USER_JOIN_REQUEST_9021, join_tags).await;

    let commands = groups.handle_join_request(join_event, &scope).unwrap();

    // Should only save the join request, not auto-approve
    assert_eq!(
        commands.len(),
        1,
        "Should only save join request for expired preauth"
    );
    match &commands[0] {
        StoreCommand::SaveSignedEvent(event, _, _) => {
            assert_eq!(event.kind, KIND_GROUP_USER_JOIN_REQUEST_9021);
        }
        _ => panic!("Expected SaveSignedEvent for join request"),
    }

    // Verify user was NOT added to the group but added to join_requests
    {
        let group = groups.get_group(&scope, group_id).unwrap();
        assert!(!group.value().is_member(&user_keys.public_key()));
        assert!(group
            .value()
            .join_requests
            .contains(&user_keys.public_key()));
    }
}

#[tokio::test]
async fn test_preauth_cleanup_on_update_state() {
    let (admin_keys, _, _) = create_test_keys().await;
    let groups = create_test_groups_with_db(&admin_keys).await;
    let scope = Scope::Default;
    let group_id = "test_cleanup_group";

    // Create group
    let create_event = create_test_event(
        &admin_keys,
        KIND_GROUP_CREATE_9007,
        vec![Tag::custom(TagKind::h(), vec![group_id])],
    )
    .await;
    groups
        .handle_group_create(create_event, &scope)
        .await
        .unwrap();

    // Create valid preauth invite that will expire soon
    let expiring_code = "expiring_code";
    let expires_at = (Timestamp::now().as_u64() + 1).to_string(); // 1 second from now
    let invite_tags = vec![
        Tag::custom(TagKind::h(), vec![group_id]),
        Tag::custom(TagKind::custom("code"), vec![expiring_code]),
        Tag::custom(TagKind::custom("preauth"), Vec::<String>::new()),
        Tag::custom(TagKind::custom("expires"), vec![expires_at]),
    ];
    let invite_event =
        create_test_event(&admin_keys, KIND_GROUP_CREATE_INVITE_9009, invite_tags).await;
    groups.handle_create_invite(invite_event, &scope).unwrap();

    // Create valid preauth invite
    let valid_code = "valid_code";
    let expires_at = (Timestamp::now().as_u64() + 3600).to_string(); // 1 hour from now
    let invite_tags = vec![
        Tag::custom(TagKind::h(), vec![group_id]),
        Tag::custom(TagKind::custom("code"), vec![valid_code]),
        Tag::custom(TagKind::custom("preauth"), Vec::<String>::new()),
        Tag::custom(TagKind::custom("expires"), vec![expires_at]),
    ];
    let invite_event =
        create_test_event(&admin_keys, KIND_GROUP_CREATE_INVITE_9009, invite_tags).await;
    groups.handle_create_invite(invite_event, &scope).unwrap();

    // Verify both invites exist
    {
        let group = groups.get_group(&scope, group_id).unwrap();
        assert!(group.value().invites.contains_key(expiring_code));
        assert!(group.value().invites.contains_key(valid_code));
    }

    // Wait for the first invite to expire
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Trigger state update (which should clean up expired codes)
    // We can trigger this by creating another invite
    let another_code = "another_code";
    let invite_tags = vec![
        Tag::custom(TagKind::h(), vec![group_id]),
        Tag::custom(TagKind::custom("code"), vec![another_code]),
        Tag::custom(TagKind::custom("preauth"), Vec::<String>::new()),
    ];
    let invite_event =
        create_test_event(&admin_keys, KIND_GROUP_CREATE_INVITE_9009, invite_tags).await;
    groups.handle_create_invite(invite_event, &scope).unwrap();

    // Verify expired code was cleaned up, but valid codes remain
    {
        let group = groups.get_group(&scope, group_id).unwrap();
        assert!(!group.value().invites.contains_key(expiring_code)); // Should be cleaned up
        assert!(group.value().invites.contains_key(valid_code)); // Should remain
        assert!(group.value().invites.contains_key(another_code)); // Should remain
    }
}

#[tokio::test]
async fn test_regular_invite_vs_preauth_invite() {
    let (admin_keys, user_keys, _) = create_test_keys().await;
    let groups = create_test_groups_with_db(&admin_keys).await;
    let scope = Scope::Default;
    let group_id = "test_regular_vs_preauth_group";

    // Create group
    let create_event = create_test_event(
        &admin_keys,
        KIND_GROUP_CREATE_9007,
        vec![Tag::custom(TagKind::h(), vec![group_id])],
    )
    .await;
    groups
        .handle_group_create(create_event, &scope)
        .await
        .unwrap();

    // Create regular invite (without preauth tag)
    let regular_code = "regular_invite";
    let invite_tags = vec![
        Tag::custom(TagKind::h(), vec![group_id]),
        Tag::custom(TagKind::custom("code"), vec![regular_code]),
    ];
    let invite_event =
        create_test_event(&admin_keys, KIND_GROUP_CREATE_INVITE_9009, invite_tags).await;
    groups.handle_create_invite(invite_event, &scope).unwrap();

    // Verify regular invite was created (not preauth)
    {
        let group = groups.get_group(&scope, group_id).unwrap();
        let invite = group.value().invites.get(regular_code).unwrap();
        assert!(!invite.is_preauth); // Should NOT be preauth
    }

    // User joins with regular invite code
    let join_tags = vec![
        Tag::custom(TagKind::h(), vec![group_id]),
        Tag::custom(TagKind::custom("code"), vec![regular_code]),
    ];
    let join_event =
        create_test_event(&user_keys, KIND_GROUP_USER_JOIN_REQUEST_9021, join_tags).await;

    let commands = groups.handle_join_request(join_event, &scope).unwrap();

    // Both regular and preauth invites generate membership events (including Kind 9000)
    // The difference is in the signer and generation method, but both should result in user being added
    assert!(
        commands.len() > 1,
        "Should generate multiple events for successful join"
    );

    // User should be added to the group
    {
        let group = groups.get_group(&scope, group_id).unwrap();
        assert!(group.value().is_member(&user_keys.public_key()));
    }
}
