// Get WordPress REST API base URL
export const getApiBase = (): string => {
  // In WordPress admin, wpApiSettings is available globally
  if (typeof window !== 'undefined' && (window as any).wpApiSettings) {
    return (window as any).wpApiSettings.root;
  }
  return '/wp-json/';
};

// Get nonce for authentication
export const getNonce = (): string => {
  if (typeof window !== 'undefined' && (window as any).wpApiSettings) {
    return (window as any).wpApiSettings.nonce;
  }
  return '';
};

// Get default headers for WordPress REST API
export const getApiHeaders = (): Record<string, string> => {
  return {
    'Content-Type': 'application/json',
    'X-WP-Nonce': getNonce(),
  };
};

// Build full URL
export const buildUrl = (path: string): string => {
  const base = getApiBase();
  return `${base}${path}`;
};

