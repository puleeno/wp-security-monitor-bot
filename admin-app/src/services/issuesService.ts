// Services chỉ export routes - HTTP calls sẽ được handle bởi RxJS ajax trong epics
export const BASE_ROUTE = 'wp-security-monitor/v1/issues';

export const issuesRoutes = {
  getIssues: (params: {
    page?: number;
    per_page?: number;
    status?: string;
    severity?: string;
    issuer?: string;
    search?: string;
  }): string => {
    const query = new URLSearchParams();
    if (params.page) query.append('page', params.page.toString());
    if (params.per_page) query.append('per_page', params.per_page.toString());
    if (params.status) query.append('status', params.status);
    if (params.severity) query.append('severity', params.severity);
    if (params.issuer) query.append('issuer', params.issuer);
    if (params.search) query.append('search', params.search);

    const queryString = query.toString();
    return `${BASE_ROUTE}${queryString ? '?' + queryString : ''}`;
  },

  markAsViewed: (issueId: number): string => `${BASE_ROUTE}/${issueId}/viewed`,

  // unmark viewed: removed

  ignoreIssue: (issueId: number): string => `${BASE_ROUTE}/${issueId}/ignore`,

  resolveIssue: (issueId: number): string => `${BASE_ROUTE}/${issueId}/resolve`,

  // Bulk updates use POST to /issues with JSON body
  bulkUpdate: (): string => `${BASE_ROUTE}`,
};

