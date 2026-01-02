import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import type { SecurityStats, BotStats } from '../types';

interface StatsState {
  security: SecurityStats | null;
  bot: BotStats | null;
  loading: boolean;
  error: string | null;
}

const initialState: StatsState = {
  security: null,
  bot: null,
  loading: false,
  error: null,
};

const statsSlice = createSlice({
  name: 'stats',
  initialState,
  reducers: {
    fetchStats: (state) => {
      state.loading = true;
      state.error = null;
    },
    fetchStatsSuccess: (state, action: PayloadAction<{ security: SecurityStats; bot: BotStats }>) => {
      state.security = action.payload.security;
      state.bot = action.payload.bot;
      state.loading = false;
    },
    fetchStatsFailure: (state, action: PayloadAction<string>) => {
      state.loading = false;
      state.error = action.payload;
    },
    startBot: (state) => {
      state.loading = true;
      state.error = null;
    },
    startBotSuccess: (state, action: PayloadAction<BotStats>) => {
      state.bot = action.payload;
      state.loading = false;
    },
    startBotFailure: (state, action: PayloadAction<string>) => {
      state.loading = false;
      state.error = action.payload;
    },
    stopBot: (state) => {
      state.loading = true;
      state.error = null;
    },
    stopBotSuccess: (state, action: PayloadAction<BotStats>) => {
      state.bot = action.payload;
      state.loading = false;
    },
    stopBotFailure: (state, action: PayloadAction<string>) => {
      state.loading = false;
      state.error = action.payload;
    },
  },
});

export const {
  fetchStats,
  fetchStatsSuccess,
  fetchStatsFailure,
  startBot,
  startBotSuccess,
  startBotFailure,
  stopBot,
  stopBotSuccess,
  stopBotFailure,
} = statsSlice.actions;
export default statsSlice.reducer;

