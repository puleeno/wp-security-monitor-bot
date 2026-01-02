import { Epic, combineEpics } from 'redux-observable';
import { of } from 'rxjs';
import { filter, map, catchError, switchMap, mergeMap, withLatestFrom } from 'rxjs/operators';
import { ajax } from 'rxjs/ajax';
import { issuesRoutes } from '../services/issuesService';
import { buildUrl, getApiHeaders } from '../services/api';
import {
  fetchIssues,
  fetchIssuesSuccess,
  fetchIssuesFailure,
  markAsViewed,
  markAsViewedSuccess,
  // unmark removed
  ignoreIssue,
  ignoreIssueSuccess,
  resolveIssue,
  resolveIssueSuccess,
  bulkAction,
  bulkActionSuccess,
  bulkActionFailure,
} from '../reducers/issuesReducer';
import { addNotification } from '../reducers/uiReducer';

// Fetch issues epic
const fetchIssuesEpic: Epic = (action$) =>
  action$.pipe(
    filter(fetchIssues.match),
    switchMap((action) => {
      const { page = 1, filters = {} } = action.payload;
      const params = {
        page,
        per_page: 20,
        ...filters,
      };

      const url = buildUrl(issuesRoutes.getIssues(params));

      return ajax({
        url,
        method: 'GET',
        headers: getApiHeaders(),
      }).pipe(
        map((response) => fetchIssuesSuccess(response.response as any)),
        catchError((error) =>
          of(
            fetchIssuesFailure(error.message || 'Không thể tải issues'),
            addNotification({
              type: 'error',
              message: `Lỗi khi tải issues: ${error.message}`,
            })
          )
        )
      );
    })
  );

// Mark as viewed epic
const markAsViewedEpic: Epic = (action$) =>
  action$.pipe(
    filter(markAsViewed.match),
    switchMap((action) => {
      const url = buildUrl(issuesRoutes.markAsViewed(action.payload));

      return ajax({
        url,
        method: 'POST',
        headers: getApiHeaders(),
      }).pipe(
        mergeMap(() =>
          of(
            markAsViewedSuccess(action.payload),
            addNotification({
              type: 'success',
              message: 'Đã đánh dấu issue là đã xem',
            })
          )
        ),
        catchError((error) =>
          of(
            addNotification({
              type: 'error',
              message: `Lỗi: ${error.message}`,
            })
          )
        )
      );
    })
  );


// Ignore issue epic
const ignoreIssueEpic: Epic = (action$) =>
  action$.pipe(
    filter(ignoreIssue.match),
    switchMap((action) => {
      const url = buildUrl(issuesRoutes.ignoreIssue(action.payload.issueId));

      return ajax({
        url,
        method: 'POST',
        headers: getApiHeaders(),
        // Một số hosting trả 415 khi body JSON; ignore cho phép không cần body
      }).pipe(
        mergeMap(() =>
          of(
            ignoreIssueSuccess(action.payload.issueId),
            addNotification({
              type: 'success',
              message: 'Issue đã được ignore',
            })
          )
        ),
        catchError((error) =>
          of(
            addNotification({
              type: 'error',
              message: `Lỗi: ${error.message}`,
            })
          )
        )
      );
    })
  );

// Resolve issue epic
const resolveIssueEpic: Epic = (action$) =>
  action$.pipe(
    filter(resolveIssue.match),
    switchMap((action) => {
      const url = buildUrl(issuesRoutes.resolveIssue(action.payload.issueId));

      return ajax({
        url,
        method: 'POST',
        headers: getApiHeaders(),
        body: { notes: action.payload.notes },
      }).pipe(
        mergeMap(() =>
          of(
            resolveIssueSuccess(action.payload.issueId),
            addNotification({
              type: 'success',
              message: 'Issue đã được resolve',
            })
          )
        ),
        catchError((error) =>
          of(
            addNotification({
              type: 'error',
              message: `Lỗi: ${error.message}`,
            })
          )
        )
      );
    })
  );

export const issuesEpic = combineEpics(
  fetchIssuesEpic,
  markAsViewedEpic,
  ignoreIssueEpic,
  resolveIssueEpic,
  // Bulk epic
  ((action$, state$) => action$.pipe(
    filter(bulkAction.match),
    switchMap((action) => {
      const url = buildUrl(issuesRoutes.bulkUpdate());
      return ajax({
        url,
        method: 'POST',
        headers: getApiHeaders(),
        body: action.payload,
      }).pipe(
        withLatestFrom(state$),
        mergeMap(([_, state]) => {
          const currentPage = (state as any).issues.currentPage;
          const filters = (state as any).issues.filters;
          return of(
            bulkActionSuccess({ ids: action.payload.ids, action: action.payload.action }),
            fetchIssues({ page: currentPage, filters }),
            addNotification({ type: 'success', message: 'Bulk action thành công' })
          );
        }),
        catchError((error) => of(
          addNotification({ type: 'error', message: `Bulk action lỗi: ${error.message}` }),
          bulkActionFailure()
        ))
      );
    })
  )) as Epic
);
