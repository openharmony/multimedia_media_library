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

import {doTaskOpsCallback} from './i_mml_task_ops';
import IMmlTaskOps from './i_mml_task_ops';
import rpc from '@ohos.rpc';

export default class MmlTaskOpsProxy implements IMmlTaskOps {
    constructor(proxy) {
        this.proxy = proxy;
    }

    doTaskOps(ops: string, taskName: string, taskExtra: string, callback: doTaskOpsCallback): void
    {
        let option = new rpc.MessageOption();
        let dataSequence = rpc.MessageSequence.create();
        let replySequence = rpc.MessageSequence.create();
        dataSequence.writeInterfaceToken(this.proxy.getDescriptor());
        dataSequence.writeString(ops);
        dataSequence.writeString(taskName);
        dataSequence.writeString(taskExtra);
        console.log('DoTaskOps proxy, ops: ' + ops + ', taskName: ' + taskName + ', taskExtra: ' + taskExtra);

        this.proxy.sendMessageRequest(MmlTaskOpsProxy.COMMAND_DO_TASK_OPS,
            dataSequence, replySequence, option).then((result: rpc.RequestResult) => {
            if (result.errCode === 0) {
                let errCodeVar = result.reply.readInt();
                if (errCodeVar !== 0) {
                    callback(errCodeVar);
                    return;
                }
                callback(errCodeVar);
            } else {
                console.log('SendMessageRequest failed, errCode: ' + result.errCode);
            }
        }).catch((e: Error) => {
            console.log('SendMessageRequest failed, message: ' + e.message);
        }).finally(() => {
            dataSequence.reclaim();
            replySequence.reclaim();
        });
    }

    static readonly COMMAND_DO_TASK_OPS = 1;
    private proxy
}
