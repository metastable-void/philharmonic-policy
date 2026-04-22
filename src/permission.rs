use crate::PolicyError;
use serde::{Deserialize, Serialize};

const UNKNOWN_PERMISSION_ATOM_PREFIX: &str = "unknown permission atom: ";

pub mod atom {
    pub const WORKFLOW_TEMPLATE_CREATE: &str = "workflow:template_create";
    pub const WORKFLOW_TEMPLATE_READ: &str = "workflow:template_read";
    pub const WORKFLOW_TEMPLATE_RETIRE: &str = "workflow:template_retire";

    pub const WORKFLOW_INSTANCE_CREATE: &str = "workflow:instance_create";
    pub const WORKFLOW_INSTANCE_READ: &str = "workflow:instance_read";
    pub const WORKFLOW_INSTANCE_EXECUTE: &str = "workflow:instance_execute";
    pub const WORKFLOW_INSTANCE_CANCEL: &str = "workflow:instance_cancel";

    pub const ENDPOINT_CREATE: &str = "endpoint:create";
    pub const ENDPOINT_ROTATE: &str = "endpoint:rotate";
    pub const ENDPOINT_RETIRE: &str = "endpoint:retire";
    pub const ENDPOINT_READ_METADATA: &str = "endpoint:read_metadata";
    pub const ENDPOINT_READ_DECRYPTED: &str = "endpoint:read_decrypted";

    pub const TENANT_PRINCIPAL_MANAGE: &str = "tenant:principal_manage";
    pub const TENANT_ROLE_MANAGE: &str = "tenant:role_manage";

    pub const TENANT_MINTING_MANAGE: &str = "tenant:minting_manage";
    pub const MINT_EPHEMERAL_TOKEN: &str = "mint:ephemeral_token";

    pub const TENANT_SETTINGS_READ: &str = "tenant:settings_read";
    pub const TENANT_SETTINGS_MANAGE: &str = "tenant:settings_manage";

    pub const AUDIT_READ: &str = "audit:read";

    pub const DEPLOYMENT_TENANT_MANAGE: &str = "deployment:tenant_manage";
    pub const DEPLOYMENT_REALM_MANAGE: &str = "deployment:realm_manage";
    pub const DEPLOYMENT_AUDIT_READ: &str = "deployment:audit_read";
}

pub const ALL_ATOMS: [&str; 22] = [
    atom::WORKFLOW_TEMPLATE_CREATE,
    atom::WORKFLOW_TEMPLATE_READ,
    atom::WORKFLOW_TEMPLATE_RETIRE,
    atom::WORKFLOW_INSTANCE_CREATE,
    atom::WORKFLOW_INSTANCE_READ,
    atom::WORKFLOW_INSTANCE_EXECUTE,
    atom::WORKFLOW_INSTANCE_CANCEL,
    atom::ENDPOINT_CREATE,
    atom::ENDPOINT_ROTATE,
    atom::ENDPOINT_RETIRE,
    atom::ENDPOINT_READ_METADATA,
    atom::ENDPOINT_READ_DECRYPTED,
    atom::TENANT_PRINCIPAL_MANAGE,
    atom::TENANT_ROLE_MANAGE,
    atom::TENANT_MINTING_MANAGE,
    atom::MINT_EPHEMERAL_TOKEN,
    atom::TENANT_SETTINGS_READ,
    atom::TENANT_SETTINGS_MANAGE,
    atom::AUDIT_READ,
    atom::DEPLOYMENT_TENANT_MANAGE,
    atom::DEPLOYMENT_REALM_MANAGE,
    atom::DEPLOYMENT_AUDIT_READ,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PermissionDocument {
    permissions: Vec<String>,
}

impl PermissionDocument {
    pub fn contains(&self, atom: &str) -> bool {
        self.permissions.iter().any(|value| value == atom)
    }

    pub fn permissions(&self) -> &[String] {
        &self.permissions
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PermissionDocumentWire {
    Bare(Vec<String>),
    Wrapped { permissions: Vec<String> },
}

impl<'de> Deserialize<'de> for PermissionDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = PermissionDocumentWire::deserialize(deserializer)?;
        let permissions = match wire {
            PermissionDocumentWire::Bare(values) => values,
            PermissionDocumentWire::Wrapped { permissions } => permissions,
        };

        for atom in &permissions {
            if !ALL_ATOMS.contains(&atom.as_str()) {
                return Err(serde::de::Error::custom(format!(
                    "{UNKNOWN_PERMISSION_ATOM_PREFIX}{atom}"
                )));
            }
        }

        Ok(Self { permissions })
    }
}

pub(crate) fn parse_permission_document(bytes: &[u8]) -> Result<PermissionDocument, PolicyError> {
    serde_json::from_slice(bytes).map_err(map_permission_document_parse_error)
}

fn map_permission_document_parse_error(error: serde_json::Error) -> PolicyError {
    if let Some(atom) = unknown_permission_atom_from_parse_error(&error) {
        return PolicyError::UnknownPermissionAtom { atom };
    }

    PolicyError::PermissionDocumentParse(error)
}

fn unknown_permission_atom_from_parse_error(error: &serde_json::Error) -> Option<String> {
    let message = error.to_string();
    let atom_and_location = message.strip_prefix(UNKNOWN_PERMISSION_ATOM_PREFIX)?;
    let atom = atom_and_location
        .split(" at line ")
        .next()
        .unwrap_or(atom_and_location);
    Some(atom.to_owned())
}

#[cfg(test)]
mod tests {
    use super::PermissionDocument;

    #[test]
    fn permission_document_parses_bare_array() {
        let doc: PermissionDocument =
            serde_json::from_slice(br#"["workflow:template_read","audit:read"]"#).unwrap();

        assert_eq!(doc.permissions(), ["workflow:template_read", "audit:read"]);
    }

    #[test]
    fn permission_document_parses_wrapped_shape() {
        let doc: PermissionDocument = serde_json::from_slice(
            br#"{"permissions":["workflow:instance_execute","tenant:role_manage"]}"#,
        )
        .unwrap();

        assert_eq!(
            doc.permissions(),
            ["workflow:instance_execute", "tenant:role_manage"]
        );
    }

    #[test]
    fn permission_document_contains_checks_membership() {
        let doc: PermissionDocument =
            serde_json::from_slice(br#"["workflow:template_read","audit:read"]"#).unwrap();

        assert!(doc.contains("audit:read"));
        assert!(!doc.contains("workflow:instance_cancel"));
    }

    #[test]
    fn permission_document_rejects_unknown_atom_bare() {
        let err = serde_json::from_slice::<PermissionDocument>(
            br#"["workflow:template_read","totally:made_up"]"#,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("unknown permission atom: totally:made_up")
        );
    }

    #[test]
    fn permission_document_rejects_unknown_atom_wrapped() {
        let err = serde_json::from_slice::<PermissionDocument>(
            br#"{"permissions":["workflow:template_read","totally:made_up"]}"#,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("unknown permission atom: totally:made_up")
        );
    }

    #[test]
    fn permission_document_accepts_empty_array() {
        let doc: PermissionDocument = serde_json::from_slice(br#"[]"#).unwrap();

        assert!(doc.permissions().is_empty());
    }
}
