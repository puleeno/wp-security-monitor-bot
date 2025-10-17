// Services chỉ export routes - HTTP calls sẽ được handle bởi RxJS ajax trong epics
const BASE_ROUTE = 'wp-security-monitor/v1';

export const statsRoutes = {
  getSecurityStats: (): string => `${BASE_ROUTE}/stats/security`,
  getBotStats: (): string => `${BASE_ROUTE}/stats/bot`,
  startBot: (): string => `${BASE_ROUTE}/bot/start`,
  stopBot: (): string => `${BASE_ROUTE}/bot/stop`,
};

