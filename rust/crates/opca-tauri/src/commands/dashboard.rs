use tauri::State;

use opca_core::services::ca::CaExpiryWarning;

use crate::commands::dto::{CaExpiryWarningDto, DashboardData};
use crate::state::AppState;

#[tauri::command]
pub async fn get_dashboard(state: State<'_, AppState>) -> Result<DashboardData, String> {
    let mut conn = state.ensure_ca()?;
    let ca = conn.ca.as_mut().ok_or("CA not available")?;

    // Extract CA bundle info first (immutable borrow)
    let ca_valid = ca.is_valid().unwrap_or(false);
    let ca_cn = ca.ca_bundle.as_ref()
        .and_then(|b| b.get_certificate_attrib("cn").ok().flatten());
    let ca_expiry = ca.ca_bundle.as_ref()
        .and_then(|b| b.get_certificate_attrib("not_after").ok().flatten());

    // Check CA expiry warning
    let ca_expiry_warning = match ca.check_ca_expiry() {
        CaExpiryWarning::Critical { days_remaining } => Some(CaExpiryWarningDto {
            level: "critical".to_string(),
            days_remaining: Some(days_remaining),
            message: format!("CA certificate expires in {days_remaining} days!"),
        }),
        CaExpiryWarning::Prominent { days_remaining } => Some(CaExpiryWarningDto {
            level: "prominent".to_string(),
            days_remaining: Some(days_remaining),
            message: format!("CA certificate expires in {days_remaining} days"),
        }),
        CaExpiryWarning::CertLifetimeExceedsCa { days_remaining, cert_lifetime_days } => Some(CaExpiryWarningDto {
            level: "cert_lifetime".to_string(),
            days_remaining: Some(days_remaining),
            message: format!(
                "CA has {days_remaining} days remaining but default cert lifetime is {cert_lifetime_days} days"
            ),
        }),
        CaExpiryWarning::None => None,
    };

    // Then process database (mutable borrow)
    let db = ca.ca_database.as_mut()
        .ok_or("Database not loaded")?;

    db.process_ca_database(None)
        .map_err(|e| e.to_string())?;

    let total_certs = db.count_certs().unwrap_or(0);

    Ok(DashboardData {
        ca_valid,
        ca_cn,
        ca_expiry,
        ca_expiry_warning,
        total_certs,
        valid_certs: db.certs_valid.len(),
        expired_certs: db.certs_expired.len(),
        expiring_certs: db.certs_expires_soon.len(),
        warning_certs: db.certs_expires_warning.len(),
        revoked_certs: db.certs_revoked.len(),
    })
}
