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
import hilog from '@ohos.hilog';
import rpc from '@ohos.rpc';

const TAG: string = '[MediaBgTask_MmlTaskOpsStub]';
const DOMAIN_NUMBER: number = 0xFF00;
const CALLER_SAID = 1013;

export default class MmlTaskOpsStub extends rpc.RemoteObject implements IMmlTaskOps {
    constructor(des: string) {
        super(des);
    }

    async onRemoteMessageRequest(code: number, data:rpc.MessageSequence, reply:rpc.MessageSequence,
        option:rpc.MessageOption): Promise<boolean> {
        if (this.getCallingUid() !== CALLER_SAID) {
            hilog.error(DOMAIN_NUMBER, TAG, `invalid CallingUid.`);
            return false;
        }

        let localDescriptor = this.getDescriptor();
        let remoteDescriptor = data.readInterfaceToken();
        if (localDescriptor !== remoteDescriptor) {
            hilog.error(DOMAIN_NUMBER, TAG, `invalid interfaceToken.`);
            return false;
        }

        switch (code) {
            case MmlTaskOpsStub.COMMAND_DO_TASK_OPS: {
                let opsVar = data.readString();
                let taskNameVar = data.readString();
                let taskExtraVar = data.readString();
                let promise = new Promise<void>((resolve, reject) => { 
                    this.doTaskOps(opsVar, taskNameVar, taskExtraVar, (errCode) => {
                        reply.writeInt(errCode);
                        resolve();
                    });
                });
                await promise;
                return true;
            }
            default: {
                hilog.error(DOMAIN_NUMBER, TAG, `invalid request code, code: ${code}`);
                break;
            }
        }
        return false;
    }

    doTaskOps(ops: string, taskName: string, taskExtra: string, callback: doTaskOpsCallback) : void {}

    static readonly COMMAND_DO_TASK_OPS = 1;
}
