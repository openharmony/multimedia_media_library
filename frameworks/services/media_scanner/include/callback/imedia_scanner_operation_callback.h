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

#ifndef IMEDIA_SCANNER_OPERATION_CALLBACK_H
#define IMEDIA_SCANNER_OPERATION_CALLBACK_H

#include "iremote_broker.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Media {
class IMediaScannerOperationCallback : public IRemoteBroker {
public:
    /**
     * @brief Callback class to be passed while calling scanner ability scanning APIs
     *
     * @param status
     * @param uri
     * @return int32_t
     */
    virtual int32_t OnScanFinishedCallback(const int32_t status, const std::string &uri, const std::string &path) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"multimedia.IMediaScannerOperationCallback");
};
} // namespace Media
} // namespace OHOS
#endif // IMEDIA_SCANNER_OPERATION_CALLBACK_H
