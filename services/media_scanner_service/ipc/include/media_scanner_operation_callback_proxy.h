/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef MEDIASCANNER_PROXY_CALLBACK_H
#define MEDIASCANNER_PROXY_CALLBACK_H

#include "iremote_proxy.h"
#include "imedia_scanner_operation_callback.h"
#include "media_scanner_const.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
class MediaScannerOperationCallbackProxy : public IRemoteProxy<IMediaScannerOperationCallback> {
public:
    explicit MediaScannerOperationCallbackProxy(const sptr<IRemoteObject> &impl);
    virtual ~MediaScannerOperationCallbackProxy() = default;

    int32_t OnScanFinishedCallback(const int32_t status, const std::string &uri, const std::string &path) override;

private:
    static inline BrokerDelegator<MediaScannerOperationCallbackProxy> delegator_;
};
} // namespace Media
} // namespace OHOS
#endif // MEDIASCANNER_PROXY_CALLBACK_H