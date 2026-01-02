import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import type { IssuersConfig } from '../types';

interface SettingsState {
  telegram: {
    enabled: boolean;
    bot_token?: string;
    chat_id?: string;
  };
  email: {
    enabled: boolean;
    to?: string;
  };
  slack: {
    enabled: boolean;
    webhook_url?: string;
  };
  log: {
    enabled: boolean;
  };
  issuers: IssuersConfig;
  savequeriesEnabled: boolean;
  loading: boolean;
  error: string | null;
}

const initialState: SettingsState = {
  telegram: {
    enabled: false,
    bot_token: '',
    chat_id: '',
  },
  email: {
    enabled: false,
    to: '',
  },
  slack: {
    enabled: false,
    webhook_url: '',
  },
  log: { enabled: true },
  issuers: {},
  savequeriesEnabled: false,
  loading: false,
  error: null,
};

const settingsSlice = createSlice({
  name: 'settings',
  initialState,
  reducers: {
    fetchSettings: (state) => {
      state.loading = true;
      state.error = null;
    },
    fetchSettingsSuccess: (state, action: PayloadAction<Partial<SettingsState>>) => {
      if (action.payload.telegram) state.telegram = action.payload.telegram;
      if (action.payload.email) state.email = action.payload.email;
      if (action.payload.slack) state.slack = action.payload.slack;
      if (action.payload.log) state.log = action.payload.log;
      if (action.payload.issuers) state.issuers = action.payload.issuers;
      state.loading = false;
      state.error = null;
    },
    fetchSettingsFailure: (state, action: PayloadAction<string>) => {
      state.loading = false;
      state.error = action.payload;
    },
    updateSettings: (state, _action: PayloadAction<Partial<SettingsState>>) => {
      state.loading = true;
    },
    updateSettingsSuccess: (state, action: PayloadAction<Partial<SettingsState>>) => {
      // Update state với data đã save - giữ nguyên UI
      if (action.payload.telegram) {
        state.telegram = { ...state.telegram, ...action.payload.telegram };
      }
      if (action.payload.email) {
        state.email = { ...state.email, ...action.payload.email };
      }
      if (action.payload.slack) {
        state.slack = { ...state.slack, ...action.payload.slack };
      }
      if (action.payload.log) {
        state.log = { ...state.log, ...action.payload.log };
      }
      state.loading = false;
    },
    updateSettingsFailure: (state, action: PayloadAction<string>) => {
      state.loading = false;
      state.error = action.payload;
    },
    fetchIssuersConfig: (state) => {
      state.loading = true;
      state.error = null;
    },
    fetchIssuersConfigSuccess: (state, action: PayloadAction<{ config: IssuersConfig; savequeries_enabled: boolean }>) => {
      state.issuers = action.payload.config;
      state.savequeriesEnabled = action.payload.savequeries_enabled;
      state.loading = false;
    },
    fetchIssuersConfigFailure: (state, action: PayloadAction<string>) => {
      state.loading = false;
      state.error = action.payload;
    },
    updateIssuersConfig: (state, _action: PayloadAction<IssuersConfig>) => {
      state.loading = true;
      state.error = null;
    },
    updateIssuersConfigSuccess: (state, action: PayloadAction<IssuersConfig>) => {
      state.issuers = action.payload;
      state.loading = false;
    },
    updateIssuersConfigFailure: (state, action: PayloadAction<string>) => {
      state.loading = false;
      state.error = action.payload;
    },
  },
});

export const {
  fetchSettings,
  fetchSettingsSuccess,
  fetchSettingsFailure,
  updateSettings,
  updateSettingsSuccess,
  updateSettingsFailure,
  fetchIssuersConfig,
  fetchIssuersConfigSuccess,
  fetchIssuersConfigFailure,
  updateIssuersConfig,
  updateIssuersConfigSuccess,
  updateIssuersConfigFailure,
} = settingsSlice.actions;

export default settingsSlice.reducer;

