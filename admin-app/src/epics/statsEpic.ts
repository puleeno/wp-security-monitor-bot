import { Epic, combineEpics } from 'redux-observable';
import { of, forkJoin } from 'rxjs';
import { filter, switchMap, map, catchError } from 'rxjs/operators';
import { ajax } from 'rxjs/ajax';
import { statsRoutes } from '../services/statsService';
import { buildUrl, getApiHeaders } from '../services/api';
import {
  fetchStats,
  fetchStatsSuccess,
  fetchStatsFailure,
  startBot,
  startBotSuccess,
  startBotFailure,
  stopBot,
  stopBotSuccess,
  stopBotFailure,
} from '../reducers/statsReducer';

const fetchStatsEpic: Epic = (action$) =>
  action$.pipe(
    filter(fetchStats.match),
    switchMap(() =>
      forkJoin({
        security: ajax({
          url: buildUrl(statsRoutes.getSecurityStats()),
          method: 'GET',
          headers: getApiHeaders(),
        }),
        bot: ajax({
          url: buildUrl(statsRoutes.getBotStats()),
          method: 'GET',
          headers: getApiHeaders(),
        }),
      }).pipe(
        map((response) =>
          fetchStatsSuccess({
            security: response.security.response as any,
            bot: response.bot.response as any,
          })
        ),
        catchError((error) => of(fetchStatsFailure(error.message || 'Không thể tải thống kê')))
      )
    )
  );

const startBotEpic: Epic = (action$) =>
  action$.pipe(
    filter(startBot.match),
    switchMap(() =>
      ajax({
        url: buildUrl(statsRoutes.startBot()),
        method: 'POST',
        headers: getApiHeaders(),
      }).pipe(
        switchMap(() => {
          // Sau khi start thành công, fetch lại bot stats
          return ajax({
            url: buildUrl(statsRoutes.getBotStats()),
            method: 'GET',
            headers: getApiHeaders(),
          }).pipe(
            map((botResponse) => startBotSuccess(botResponse.response as any)),
            catchError((error) => of(startBotFailure(error.message || 'Không thể tải thông tin bot')))
          );
        }),
        catchError((error) => of(startBotFailure(error.response?.message || 'Không thể khởi động bot')))
      )
    )
  );

const stopBotEpic: Epic = (action$) =>
  action$.pipe(
    filter(stopBot.match),
    switchMap(() =>
      ajax({
        url: buildUrl(statsRoutes.stopBot()),
        method: 'POST',
        headers: getApiHeaders(),
      }).pipe(
        switchMap(() => {
          // Sau khi stop thành công, fetch lại bot stats
          return ajax({
            url: buildUrl(statsRoutes.getBotStats()),
            method: 'GET',
            headers: getApiHeaders(),
          }).pipe(
            map((botResponse) => stopBotSuccess(botResponse.response as any)),
            catchError((error) => of(stopBotFailure(error.message || 'Không thể tải thông tin bot')))
          );
        }),
        catchError((error) => of(stopBotFailure(error.response?.message || 'Không thể dừng bot')))
      )
    )
  );

export const statsEpic = combineEpics(fetchStatsEpic, startBotEpic, stopBotEpic);
