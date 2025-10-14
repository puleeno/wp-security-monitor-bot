import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import type { Issue, IssuesResponse } from '../types';

interface IssuesState {
  items: Issue[];
  total: number;
  pages: number;
  currentPage: number;
  perPage: number;
  loading: boolean;
  error: string | null;
  filters: {
    status?: string;
    severity?: string;
    issuer?: string;
    search?: string;
  };
}

const initialState: IssuesState = {
  items: [],
  total: 0,
  pages: 0,
  currentPage: 1,
  perPage: 20,
  loading: false,
  error: null,
  filters: {},
};

const issuesSlice = createSlice({
  name: 'issues',
  initialState,
  reducers: {
    // Actions
    fetchIssues: (state, action: PayloadAction<{ page?: number; filters?: IssuesState['filters'] }>) => {
      state.loading = true;
      state.error = null;
      if (action.payload.page) {
        state.currentPage = action.payload.page;
      }
      if (action.payload.filters) {
        state.filters = action.payload.filters;
      }
    },
    fetchIssuesSuccess: (state, action: PayloadAction<IssuesResponse>) => {
      state.items = action.payload.issues;
      state.total = action.payload.total;
      state.pages = action.payload.pages;
      state.currentPage = action.payload.current_page;
      state.perPage = action.payload.per_page;
      state.loading = false;
    },
    fetchIssuesFailure: (state, action: PayloadAction<string>) => {
      state.loading = false;
      state.error = action.payload;
    },

    markAsViewed: (_state, _action: PayloadAction<number>) => {
      // Epic sẽ handle API call
    },
    markAsViewedSuccess: (state, action: PayloadAction<number>) => {
      const issue = state.items.find(i => i.id === action.payload);
      if (issue) {
        issue.viewed = true;
        issue.viewed_at = new Date().toISOString();
      }
    },

    unmarkAsViewed: (_state, _action: PayloadAction<number>) => {
      // Epic sẽ handle API call
    },
    unmarkAsViewedSuccess: (state, action: PayloadAction<number>) => {
      const issue = state.items.find(i => i.id === action.payload);
      if (issue) {
        issue.viewed = false;
        issue.viewed_by = null;
        issue.viewed_at = null;
      }
    },

    ignoreIssue: (_state, _action: PayloadAction<{ issueId: number; reason: string }>) => {
      // Epic sẽ handle API call
    },
    ignoreIssueSuccess: (state, action: PayloadAction<number>) => {
      const issue = state.items.find(i => i.id === action.payload);
      if (issue) {
        issue.is_ignored = true;
        issue.status = 'ignored';
      }
    },

    resolveIssue: (_state, _action: PayloadAction<{ issueId: number; notes: string }>) => {
      // Epic sẽ handle API call
    },
    resolveIssueSuccess: (state, action: PayloadAction<number>) => {
      const issue = state.items.find(i => i.id === action.payload);
      if (issue) {
        issue.status = 'resolved';
      }
    },
  },
});

export const {
  fetchIssues,
  fetchIssuesSuccess,
  fetchIssuesFailure,
  markAsViewed,
  markAsViewedSuccess,
  unmarkAsViewed,
  unmarkAsViewedSuccess,
  ignoreIssue,
  ignoreIssueSuccess,
  resolveIssue,
  resolveIssueSuccess,
} = issuesSlice.actions;

export default issuesSlice.reducer;

