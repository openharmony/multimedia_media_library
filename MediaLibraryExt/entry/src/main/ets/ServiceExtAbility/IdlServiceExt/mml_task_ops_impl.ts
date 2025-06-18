/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import IdlServiceExtStub from './mml_task_ops_stub';
import hilog from '@ohos.hilog';
import type { doTaskOpsCallback } from './i_mml_task_ops';
// @ts-ignore
import mediaserviceext from '@ohos.multimedia.mediaserviceext';

const TAG: string = '[MediaBgTask_MmlTaskOpsImpl]';
const DOMAIN_NUMBER: number = 0xFF00;

export default class ServiceExtImpl extends IdlServiceExtStub {
  constructor(des: string) {
    super(des);
  }

  doTaskOps(ops: string, taskName: string, taskExtra: string, callback: doTaskOpsCallback): void {
    let ret : number = mediaserviceext.doTaskOps(ops, taskName, taskExtra);
    hilog.info(DOMAIN_NUMBER, TAG, `DoTaskOps, ret: ${ret}.`);
    callback(ret);
  }
}
