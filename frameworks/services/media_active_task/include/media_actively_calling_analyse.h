/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_MEDIA_ACTIVELY_CALLING_ANALYSE_H
#define OHOS_MEDIA_ACTIVELY_CALLING_ANALYSE_H

#include <mutex>
#include <vector>
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "media_log.h"
#include "napi_remote_object.h"
#include "uv.h"
#include "imedia_analyse_service.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace Media {
class MediaActivelyCallingAnalyse : public IRemoteProxy<IMediaAnalyseService> {
public:
    explicit MediaActivelyCallingAnalyse(const sptr<IRemoteObject> &impl);
    ~MediaActivelyCallingAnalyse();
    bool SendTransactCmd(int32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

private:
    const int32_t SAID = 10120;
    static inline BrokerDelegator<MediaActivelyCallingAnalyse> delegator_;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_ACTIVELY_CALLING_ANALYSE_H