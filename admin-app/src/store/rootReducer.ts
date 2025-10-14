import { combineReducers } from '@reduxjs/toolkit';
import issuesReducer from '../reducers/issuesReducer';
import statsReducer from '../reducers/statsReducer';
import settingsReducer from '../reducers/settingsReducer';
import uiReducer from '../reducers/uiReducer';

export const rootReducer = combineReducers({
  issues: issuesReducer,
  stats: statsReducer,
  settings: settingsReducer,
  ui: uiReducer,
});

