## Summary

<!-- 1-3 sentences: what does this PR do and why? -->

## Changes

<!-- Bullet list of key changes. Group by crate/component if touching multiple areas. -->

-

## Type of Change

<!-- Check all that apply -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Enhancement (improvement to existing functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Refactoring (no functional change)
- [ ] Documentation
- [ ] CI / DevOps
- [ ] Security fix

## Testing

<!-- Describe how you verified the changes. Include test names if applicable. -->

- [ ] Added new tests for the changes
- [ ] CI passes for the touched area
- [ ] Rust changes were verified in the remote `vigilyx-rust-builder` workflow, or are covered by CI
- [ ] Manually tested on the remote deployment when runtime behavior changed

## Checklist

<!-- All items must be checked before merging -->

- [ ] For Rust changes: `docker exec vigilyx-rust-builder cargo clippy --workspace -- -D warnings` passes, or CI covers it
- [ ] For Rust changes: `docker exec vigilyx-rust-builder cargo test --workspace` passes, or CI covers it
- [ ] For frontend changes: `npx tsc --noEmit` and `npx vite build` pass
- [ ] CI is green for this branch or PR
- [ ] Documentation / examples were updated if behavior, deploy flow, or configuration changed
- [ ] No hardcoded secrets, passwords, or credentials
- [ ] No `unwrap()` / `expect()` in production code without `// SAFETY:` comment
- [ ] Logs do not leak PII or sensitive data
- [ ] Error responses do not expose internal details

## Security Considerations

<!-- If this PR touches auth, crypto, input validation, or data handling, describe the security implications. Write "N/A" if not applicable. -->

## Screenshots

<!-- If there are UI changes, attach before/after screenshots. Delete this section if not applicable. -->

## Related Issues

<!-- Link related issues: Fixes #123, Relates to #456 -->
