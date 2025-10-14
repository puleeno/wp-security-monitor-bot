import { Epic, combineEpics } from 'redux-observable';
import { of } from 'rxjs';
import { filter, switchMap, map, catchError, mergeMap } from 'rxjs/operators';
import { ajax } from 'rxjs/ajax';
import { buildUrl, getApiHeaders } from '../services/api';
import {
  fetchSettings,
  fetchSettingsSuccess,
  fetchSettingsFailure,
  updateSettings,
  updateSettingsSuccess,
  updateSettingsFailure,
} from '../reducers/settingsReducer';
import { addNotification } from '../reducers/uiReducer';

const BASE_ROUTE = 'wp-security-monitor/v1/settings';

// Fetch settings epic
const fetchSettingsEpic: Epic = (action$) =>
  action$.pipe(
    filter(fetchSettings.match),
    switchMap(() =>
      ajax({
        url: buildUrl(BASE_ROUTE),
        method: 'GET',
        headers: getApiHeaders(),
      }).pipe(
        map((response) => fetchSettingsSuccess(response.response as any)),
        catchError((error) => of(fetchSettingsFailure(error.message || 'Không thể tải settings')))
      )
    )
  );

// Update settings epic
const updateSettingsEpic: Epic = (action$) =>
  action$.pipe(
    filter(updateSettings.match),
    switchMap((action) =>
      ajax({
        url: buildUrl(BASE_ROUTE),
        method: 'POST',
        headers: getApiHeaders(),
        body: action.payload,
      }).pipe(
        mergeMap(() =>
          of(
            updateSettingsSuccess(action.payload),
            addNotification({
              type: 'success',
              message: 'Settings đã được lưu thành công',
            })
          )
        ),
        catchError((error) =>
          of(
            updateSettingsFailure(error.message || 'Không thể lưu settings'),
            addNotification({
              type: 'error',
              message: `Lỗi: ${error.message}`,
            })
          )
        )
      )
    )
  );

export const settingsEpic = combineEpics(fetchSettingsEpic, updateSettingsEpic);
