/**
 * Auth0 Action (Login flow, post-login trigger)
 * Custom risk condition: blocks login if there have been too many recent
 * failed login attempts, as a velocity-based anomaly signal.
 */
exports.onExecutePostLogin = async (event, api) => {
  const MAX_FAILED_LOGINS_5MIN = 5;
  const recentFailedLogins = event.stats?.logins_count || 0;

  if (recentFailedLogins > MAX_FAILED_LOGINS_5MIN) {
    api.access.deny(
      "risk_block_velocity",
      "Login denied: too many recent failed login attempts"
    );
  }
};