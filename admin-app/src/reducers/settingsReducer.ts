import { createSlice, PayloadAction } from '@reduxjs/toolkit';

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
  issuers: Record<string, { enabled: boolean }>;
  loading: boolean;
  error: string | null;
}

const initialState: SettingsState = {
  telegram: { enabled: false },
  email: { enabled: false },
  slack: { enabled: false },
  log: { enabled: true },
  issuers: {},
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
      Object.assign(state, action.payload);
      state.loading = false;
    },
    fetchSettingsFailure: (state, action: PayloadAction<string>) => {
      state.loading = false;
      state.error = action.payload;
    },
    updateSettings: (state, _action: PayloadAction<Partial<SettingsState>>) => {
      state.loading = true;
    },
    updateSettingsSuccess: (state, action: PayloadAction<Partial<SettingsState>>) => {
      Object.assign(state, action.payload);
      state.loading = false;
    },
    updateSettingsFailure: (state, action: PayloadAction<string>) => {
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
} = settingsSlice.actions;

export default settingsSlice.reducer;

