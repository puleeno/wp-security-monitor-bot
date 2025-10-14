import { combineEpics } from 'redux-observable';
import { issuesEpic } from '../epics/issuesEpic';
import { statsEpic } from '../epics/statsEpic';
import { settingsEpic } from '../epics/settingsEpic';

export const rootEpic = combineEpics(issuesEpic, statsEpic, settingsEpic);

