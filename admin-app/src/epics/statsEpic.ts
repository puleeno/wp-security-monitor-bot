import { Epic, combineEpics } from 'redux-observable';
import { of, forkJoin } from 'rxjs';
import { filter, switchMap, map, catchError } from 'rxjs/operators';
import { ajax } from 'rxjs/ajax';
import { statsRoutes } from '../services/statsService';
import { buildUrl, getApiHeaders } from '../services/api';
import { fetchStats, fetchStatsSuccess, fetchStatsFailure } from '../reducers/statsReducer';

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

export const statsEpic = combineEpics(fetchStatsEpic);
