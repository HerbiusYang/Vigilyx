use super::*;

#[test]
fn system_seed_keywords_are_normalized_out_of_user_added() {
    let system_seed = KeywordOverrides {
        phishing_keywords: KeywordCategoryOverride {
            added: vec!["account suspended".to_string()],
            removed: vec![],
        },
        ..KeywordOverrides::default()
    };

    let legacy_overrides = KeywordOverrides {
        phishing_keywords: KeywordCategoryOverride {
            added: vec!["account suspended".to_string()],
            removed: vec![],
        },
        ..KeywordOverrides::default()
    };

    let normalized = normalize_user_keyword_overrides(&system_seed, &legacy_overrides);
    assert!(normalized.phishing_keywords.added.is_empty());

    let builtin = get_builtin_keyword_lists(&system_seed);
    let builtin_phishing = builtin["phishing_keywords"]
        .as_array()
        .expect("builtin phishing keyword array");
    assert!(
        builtin_phishing
            .iter()
            .any(|value| value.as_str() == Some("account suspended"))
    );
}

#[test]
fn seeded_keywords_can_still_be_removed_as_user_delta() {
    let system_seed = KeywordOverrides {
        bec_phrases: KeywordCategoryOverride {
            added: vec!["same day wire".to_string()],
            removed: vec![],
        },
        ..KeywordOverrides::default()
    };

    let overrides = KeywordOverrides {
        bec_phrases: KeywordCategoryOverride {
            added: vec![],
            removed: vec!["same day wire".to_string()],
        },
        ..KeywordOverrides::default()
    };

    let normalized = normalize_user_keyword_overrides(&system_seed, &overrides);
    assert_eq!(
        normalized.bec_phrases.removed,
        vec!["same day wire".to_string()]
    );

    let effective = ContentScanModule::new_with_keyword_lists(build_effective_keyword_lists(
        &system_seed,
        &normalized,
    ))
    .effective_keywords();
    let effective_bec = effective["bec_phrases"]
        .as_array()
        .expect("effective bec phrase array");
    assert!(
        !effective_bec
            .iter()
            .any(|value| value.as_str() == Some("same day wire"))
    );
}
