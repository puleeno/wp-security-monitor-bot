// Mapping issuer keys to friendly display names
export const issuerNames: Record<string, string> = {
  // Realtime issuers
  'realtime_brute_force': '🔴 Brute Force Attack',
  'realtime_failed_login': '⚠️ Failed Login Attempt',
  'realtime_redirect': '🔀 Suspicious Redirect',
  'realtime_user_registration': '👤 New User Registration',

  // Scheduled issuers
  'failed_logins': '🔑 Failed Login Monitor',
  'brute_force': '🛡️ Brute Force Monitor',
  'suspicious_login_patterns': '🕵️ Suspicious Login Patterns',
  'file_changes': '📁 File Change Monitor',
  'malware_scanner': '🦠 Malware Scanner',
  'plugin_changes': '🔌 Plugin Changes',
  'theme_changes': '🎨 Theme Changes',
  'user_changes': '👥 User Changes',
  'permission_changes': '🔐 Permission Changes',
  'database_changes': '💾 Database Changes',
  'wp_config_changes': '⚙️ Config Changes',

  // Class name mappings (for backward compatibility)
  'PluginThemeUploadIssuer': '☠️ Malware Upload Scanner',
  'FatalErrorIssuer': '🚨 Fatal Error Monitor',
  'PerformanceIssuer': '⚡ Performance Monitor',
  'RealtimeRedirectIssuer': '🔀 Redirect Monitor',
};

// Get friendly name for issuer
export const getIssuerName = (issuerKey: string): string => {
  return issuerNames[issuerKey] || issuerKey.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase());
};

// Get issuer category
export const getIssuerCategory = (issuerKey: string): 'realtime' | 'scheduled' => {
  return issuerKey.startsWith('realtime_') ? 'realtime' : 'scheduled';
};

// Get issuer icon
export const getIssuerIcon = (issuerKey: string): string => {
  const icons: Record<string, string> = {
    'realtime_brute_force': '🔴',
    'realtime_failed_login': '⚠️',
    'realtime_redirect': '🔀',
    'realtime_user_registration': '👤',
    'failed_logins': '🔑',
    'brute_force': '🛡️',
    'suspicious_login_patterns': '🕵️',
    'file_changes': '📁',
    'malware_scanner': '🦠',
    'plugin_changes': '🔌',
    'theme_changes': '🎨',
    'user_changes': '👥',
    'permission_changes': '🔐',
    'database_changes': '💾',
    'wp_config_changes': '⚙️',
  };
  return icons[issuerKey] || '📋';
};

