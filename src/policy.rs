//! Policy parsing and evaluation for the PABS-CRF scheme
//!
//! Implements a strict access-policy parser supporting AND / OR / NOT operators,
//! with explicit precedence, parenthesis handling, and whitespace compatibility.

use crate::errors::{PabsCrfError, PabsCrfResult};
use std::collections::HashSet;

const RESERVED_TOKENS: &[&str] = &["AND", "OR", "NOT", "and", "or", "not"];

/// Attribute policy
#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "PolicyDeserHelper")]
pub struct Policy {
    root: Option<PolicyRule>,
}

#[derive(serde::Deserialize)]
struct PolicyDeserHelper {
    root: Option<PolicyRule>,
}

impl TryFrom<PolicyDeserHelper> for Policy {
    type Error = String;
    fn try_from(helper: PolicyDeserHelper) -> Result<Self, Self::Error> {
        if let Some(ref rule) = helper.root {
            Self::reject_not(rule)?;
        }
        Ok(Policy { root: helper.root })
    }
}

/// Policy rule - syntax tree node
#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
enum PolicyRule {
    /// Leaf node: a single attribute
    Attribute(String),
    /// Logical AND: all child rules must be satisfied
    And(Vec<PolicyRule>),
    /// Logical OR: at least one child rule must be satisfied
    Or(Vec<PolicyRule>),
    /// Logical NOT: the child rule must not be satisfied
    Not(Box<PolicyRule>),
}

impl Policy {
    /// Validate that an attribute name conforms to the allowed character set
    /// and does not collide with reserved policy tokens.
    pub fn validate_attribute_name(name: &str) -> PabsCrfResult<()> {
        if name.is_empty() {
            return Err(PabsCrfError::PolicyError(
                "Empty attribute name".to_string(),
            ));
        }
        if name.chars().any(|c| c.is_whitespace()) {
            return Err(PabsCrfError::PolicyError(format!(
                "Attribute name '{}' contains whitespace",
                name
            )));
        }
        if RESERVED_TOKENS.iter().any(|t| name == *t) {
            return Err(PabsCrfError::PolicyError(format!(
                "Attribute name '{}' is a reserved token",
                name
            )));
        }
        if !name.chars().all(|c| {
            c.is_alphanumeric() || c == '_' || c == '-' || c == ':' || c == '.' || c == ','
        }) {
            return Err(PabsCrfError::PolicyError(format!(
                "Attribute name '{}' contains invalid characters",
                name
            )));
        }
        Ok(())
    }

    /// Parse a policy from string
    ///
    /// Supported formats:
    /// - Single attribute: "admin"
    /// - AND: "admin AND finance" or "admin AND finance AND user"
    /// - OR: "admin OR user" or "admin OR user OR manager"
    /// - Mixed: "(admin AND finance) OR (user AND manager)"
    /// - NOT: "NOT admin"
    ///
    /// Returns error on invalid policies instead of silent fallback.
    pub fn parse(policy_str: &str) -> PabsCrfResult<Self> {
        let trimmed = policy_str.trim();

        if trimmed.is_empty() {
            return Err(PabsCrfError::PolicyError("Empty policy string".to_string()));
        }

        // Validate attribute names (no special characters that could cause issues)
        Self::validate_policy_string(trimmed)?;

        // Handle parenthesized expressions
        if trimmed.starts_with('(') && trimmed.ends_with(')') {
            if Self::is_balanced_paren_group(trimmed) {
                return Self::parse(&trimmed[1..trimmed.len() - 1]);
            }
        }

        // Handle NOT operator (case-insensitive)
        if let Some(_rest) = Self::strip_prefix_case_insensitive(trimmed, "NOT ") {
            return Err(PabsCrfError::PolicyError(
                "NOT operator is currently not supported in LSSS-based attribute mapping (Phase C)"
                    .to_string(),
            ));
            /*
            // Original implementation kept for reference
            let inner = Self::parse(rest.trim())?;
            return Ok(Self {
                root: Some(PolicyRule::Not(Box::new(
                    inner.root.ok_or_else(|| PabsCrfError::PolicyError("NOT operator requires valid inner expression".to_string()))?
                )))
            });
            */
        }

        // Handle OR operator (case-insensitive, left-associative)
        if let Some(or_split) = Self::split_top_level_or(trimmed) {
            let left = Self::parse(or_split.0)?;
            let right = Self::parse(or_split.1)?;
            let mut or_rules = Vec::new();
            Self::collect_or_rules(&left, &mut or_rules);
            Self::collect_or_rules(&right, &mut or_rules);

            if or_rules.is_empty() {
                return Err(PabsCrfError::PolicyError(
                    "OR expression must have at least one operand".to_string(),
                ));
            }
            return Ok(Self {
                root: Some(PolicyRule::Or(or_rules)),
            });
        }

        // Handle AND operator (case-insensitive, left-associative)
        if let Some(and_split) = Self::split_top_level_and(trimmed) {
            let left = Self::parse(and_split.0)?;
            let right = Self::parse(and_split.1)?;
            let mut and_rules = Vec::new();
            Self::collect_and_rules(&left, &mut and_rules);
            Self::collect_and_rules(&right, &mut and_rules);

            if and_rules.is_empty() {
                return Err(PabsCrfError::PolicyError(
                    "AND expression must have at least one operand".to_string(),
                ));
            }
            return Ok(Self {
                root: Some(PolicyRule::And(and_rules)),
            });
        }

        // Single attribute - validate it's not empty
        if trimmed.is_empty() {
            return Err(PabsCrfError::PolicyError(
                "Empty attribute name".to_string(),
            ));
        }

        Self::validate_attribute_name(trimmed)?;
        Ok(Self {
            root: Some(PolicyRule::Attribute(trimmed.to_string())),
        })
    }

    fn reject_not(rule: &PolicyRule) -> Result<(), String> {
        match rule {
            PolicyRule::Not(_) => Err(
                "NOT operator not supported in deserialized Policy (LSSS-based mapping is monotone-only)".into(),
            ),
            PolicyRule::And(rules) | PolicyRule::Or(rules) => {
                rules.iter().try_for_each(Self::reject_not)
            }
            PolicyRule::Attribute(_) => Ok(()),
        }
    }

    /// Strip prefix case-insensitively
    fn strip_prefix_case_insensitive<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
        if s.len() < prefix.len() {
            return None;
        }

        // Use character-based comparison to avoid UTF-8 boundary issues
        let s_chars: Vec<char> = s.chars().collect();
        let prefix_chars: Vec<char> = prefix.chars().collect();

        if s_chars.len() < prefix_chars.len() {
            return None;
        }

        // Check if first prefix_chars.len() characters match (case-insensitive)
        for (sc, pc) in s_chars.iter().zip(prefix_chars.iter()) {
            if !sc.eq_ignore_ascii_case(pc) {
                return None;
            }
        }

        // Return substring after the prefix using char_indices for safe boundary
        let prefix_char_count = prefix.chars().count();
        let byte_offset = s
            .char_indices()
            .nth(prefix_char_count)
            .map(|(idx, _)| idx)
            .unwrap_or(s.len());

        Some(&s[byte_offset..])
    }

    /// Validate policy string for potentially dangerous patterns
    fn validate_policy_string(s: &str) -> PabsCrfResult<()> {
        // Check for unbalanced parentheses
        let mut depth = 0;
        for c in s.chars() {
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
            }
            if depth < 0 {
                return Err(PabsCrfError::PolicyError(
                    "Unbalanced parentheses in policy string".to_string(),
                ));
            }
        }
        if depth != 0 {
            return Err(PabsCrfError::PolicyError(
                "Unbalanced parentheses in policy string".to_string(),
            ));
        }

        // Check for empty nested parentheses
        if s.contains("()") {
            return Err(PabsCrfError::PolicyError(
                "Empty parentheses in policy string".to_string(),
            ));
        }

        // Check for consecutive operators
        let upper = s.to_uppercase();
        if upper.contains("AND AND") || upper.contains("OR OR") || upper.contains("NOT NOT NOT") {
            return Err(PabsCrfError::PolicyError(
                "Consecutive operators in policy string".to_string(),
            ));
        }

        // Check if ends with operator
        if upper.ends_with(" AND") || upper.ends_with(" OR") || upper.ends_with(" NOT") {
            return Err(PabsCrfError::PolicyError(
                "Policy string ends with an operator".to_string(),
            ));
        }

        // Check if starts with binary operator
        if upper.starts_with("AND ") || upper.starts_with("OR ") {
            return Err(PabsCrfError::PolicyError(
                "Policy string starts with a binary operator".to_string(),
            ));
        }

        // Check for very deeply nested policies (prevent stack overflow)
        let max_depth = s
            .chars()
            .fold((0, 0), |(max, current), c| {
                if c == '(' {
                    (max.max(current + 1), current + 1)
                } else if c == ')' {
                    (max, current - 1)
                } else {
                    (max, current)
                }
            })
            .0;

        if max_depth > 20 {
            return Err(PabsCrfError::PolicyError(format!(
                "Policy too deeply nested (max depth 20, got {})",
                max_depth
            )));
        }

        Ok(())
    }

    /// Check if the string is a balanced paren group
    fn is_balanced_paren_group(s: &str) -> bool {
        if !s.starts_with('(') || !s.ends_with(')') {
            return false;
        }
        let mut depth = 0;
        for (i, c) in s.chars().enumerate() {
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
            }
            // If depth reaches 0 before the end, it's not a single group
            if depth == 0 && i < s.len() - 1 {
                return false;
            }
        }
        depth == 0
    }

    /// Split by OR at the top level (outside parentheses), case-insensitive
    fn split_top_level_or(s: &str) -> Option<(&str, &str)> {
        Self::split_top_level_operator(s, "or")
    }

    /// Split by AND at the top level (outside parentheses), case-insensitive
    fn split_top_level_and(s: &str) -> Option<(&str, &str)> {
        Self::split_top_level_operator(s, "and")
    }

    /// Generic case-insensitive top-level operator splitter
    fn split_top_level_operator<'a>(s: &'a str, op_lower: &str) -> Option<(&'a str, &'a str)> {
        let mut depth = 0;
        let chars: Vec<char> = s.chars().collect();
        let op_chars: Vec<char> = op_lower.chars().collect();
        let op_len = op_chars.len();

        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '(' {
                depth += 1;
                i += 1;
            } else if chars[i] == ')' {
                depth -= 1;
                i += 1;
            } else if depth == 0 && i + op_len <= chars.len() {
                // Check if the substring matches the operator (case-insensitive)
                let substring: String = chars[i..i + op_len].iter().collect();
                let is_match = substring.eq_ignore_ascii_case(op_lower);

                if is_match {
                    // Ensure operator has word boundaries (not part of a larger word)
                    // Check character before operator
                    let before_ok = i == 0 || chars[i - 1] == ' ';
                    // Check character after operator
                    let after_ok = i + op_len >= chars.len() || chars[i + op_len] == ' ';

                    if before_ok && after_ok {
                        // Find byte offset for left end
                        let left_byte_end = s
                            .char_indices()
                            .take(i)
                            .last()
                            .map(|(idx, c)| idx + c.len_utf8())
                            .unwrap_or(0);

                        // Skip past operator and any trailing whitespace for right start
                        let mut right_char_idx = i + op_len;
                        while right_char_idx < chars.len() && chars[right_char_idx] == ' ' {
                            right_char_idx += 1;
                        }

                        let right_byte_start = s
                            .char_indices()
                            .nth(right_char_idx)
                            .map(|(idx, _)| idx)
                            .unwrap_or(s.len());

                        let left = &s[..left_byte_end].trim();
                        let right = &s[right_byte_start..].trim();
                        if !left.is_empty() && !right.is_empty() {
                            return Some((left, right));
                        }
                    }
                }
                i += 1;
            } else {
                i += 1;
            }
        }
        None
    }

    /// Collect OR rules from a policy
    fn collect_or_rules(policy: &Self, rules: &mut Vec<PolicyRule>) {
        if let Some(ref rule) = policy.root {
            match rule {
                PolicyRule::Or(inner_rules) => {
                    rules.extend(inner_rules.clone());
                }
                _ => {
                    rules.push(rule.clone());
                }
            }
        }
    }

    /// Collect AND rules from a policy
    fn collect_and_rules(policy: &Self, rules: &mut Vec<PolicyRule>) {
        if let Some(ref rule) = policy.root {
            match rule {
                PolicyRule::And(inner_rules) => {
                    rules.extend(inner_rules.clone());
                }
                _ => {
                    rules.push(rule.clone());
                }
            }
        }
    }

    /// Check if attributes satisfy the policy
    pub fn satisfies(&self, attributes: &[&str]) -> bool {
        let attr_set: HashSet<&str> = attributes.iter().cloned().collect();
        if let Some(ref rule) = self.root {
            Self::evaluate_rule(rule, &attr_set)
        } else {
            true // Empty policy is satisfied by anyone
        }
    }

    /// Evaluate a policy rule
    fn evaluate_rule(rule: &PolicyRule, attributes: &HashSet<&str>) -> bool {
        match rule {
            PolicyRule::Attribute(attr) => attributes.contains(attr.as_str()),
            PolicyRule::And(rules) => rules.iter().all(|r| Self::evaluate_rule(r, attributes)),
            PolicyRule::Or(rules) => rules.iter().any(|r| Self::evaluate_rule(r, attributes)),
            PolicyRule::Not(rule) => !Self::evaluate_rule(rule, attributes),
        }
    }

    /// Convert policy to LSSS sharing matrix
    pub fn to_lsss(&self) -> PabsCrfResult<crate::lsss::LSSSShareMatrix> {
        let policy_str = self.to_string();
        crate::lsss::LSSSShareMatrix::from_boolean_tree(&policy_str)
    }
}

impl ToString for Policy {
    fn to_string(&self) -> String {
        // Convert policy to string representation
        if let Some(ref rule) = self.root {
            Self::rule_to_string(rule)
        } else {
            "true".to_string()
        }
    }
}

impl Policy {
    fn rule_to_string(rule: &PolicyRule) -> String {
        match rule {
            PolicyRule::Attribute(attr) => attr.clone(),
            PolicyRule::And(rules) => {
                let mut parts: Vec<String> = rules.iter().map(Self::rule_to_string).collect();
                parts.sort();
                format!("({})", parts.join(" AND "))
            }
            PolicyRule::Or(rules) => {
                let mut parts: Vec<String> = rules.iter().map(Self::rule_to_string).collect();
                parts.sort();
                format!("({})", parts.join(" OR "))
            }
            PolicyRule::Not(rule) => format!("NOT {}", Self::rule_to_string(rule)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_rejects_not() {
        let result = Policy::parse("NOT admin");
        assert!(result.is_err(), "Parser should reject NOT operator");
    }

    #[test]
    fn valid_policy_bincode_roundtrip() {
        let cases = vec![
            "admin",
            "admin AND finance",
            "admin OR finance",
            "(admin AND finance) OR user",
        ];
        for s in cases {
            let policy = Policy::parse(s).unwrap();
            let bytes = bincode::serialize(&policy).unwrap();
            let de: Policy = bincode::deserialize(&bytes).unwrap();
            assert_eq!(policy, de, "Round-trip failed for: {}", s);
        }
    }

    #[test]
    fn bincode_rejects_not_root() {
        let malicious = Policy {
            root: Some(PolicyRule::Not(Box::new(PolicyRule::Attribute(
                "admin".into(),
            )))),
        };
        let bytes = bincode::serialize(&malicious).unwrap();
        let result: Result<Policy, _> = bincode::deserialize(&bytes);
        assert!(result.is_err(), "Deserialization must reject NOT at root");
    }

    #[test]
    fn bincode_rejects_not_nested_in_and() {
        let malicious = Policy {
            root: Some(PolicyRule::And(vec![
                PolicyRule::Attribute("admin".into()),
                PolicyRule::Not(Box::new(PolicyRule::Attribute("finance".into()))),
            ])),
        };
        let bytes = bincode::serialize(&malicious).unwrap();
        let result: Result<Policy, _> = bincode::deserialize(&bytes);
        assert!(
            result.is_err(),
            "Deserialization must reject NOT nested in AND"
        );
    }

    #[test]
    fn bincode_rejects_not_nested_in_or() {
        let malicious = Policy {
            root: Some(PolicyRule::Or(vec![
                PolicyRule::Attribute("admin".into()),
                PolicyRule::Not(Box::new(PolicyRule::Attribute("finance".into()))),
            ])),
        };
        let bytes = bincode::serialize(&malicious).unwrap();
        let result: Result<Policy, _> = bincode::deserialize(&bytes);
        assert!(
            result.is_err(),
            "Deserialization must reject NOT nested in OR"
        );
    }

    #[test]
    fn bincode_rejects_deeply_nested_not() {
        let malicious = Policy {
            root: Some(PolicyRule::And(vec![
                PolicyRule::Or(vec![
                    PolicyRule::Attribute("a".into()),
                    PolicyRule::Not(Box::new(PolicyRule::Attribute("b".into()))),
                ]),
                PolicyRule::Attribute("c".into()),
            ])),
        };
        let bytes = bincode::serialize(&malicious).unwrap();
        let result: Result<Policy, _> = bincode::deserialize(&bytes);
        assert!(
            result.is_err(),
            "Deserialization must reject deeply nested NOT"
        );
    }

    #[test]
    fn empty_policy_roundtrip() {
        let policy = Policy { root: None };
        let bytes = bincode::serialize(&policy).unwrap();
        let de: Policy = bincode::deserialize(&bytes).unwrap();
        assert_eq!(policy, de);
    }
}
