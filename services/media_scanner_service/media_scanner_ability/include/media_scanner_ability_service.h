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

#ifndef MEDIA_SCANNER_ABILITY_SERVICE_H
#define MEDIA_SCANNER_ABILITY_SERVICE_H

#include <map>
#include "media_scanner.h"
#include "media_scanner_ability_stub.h"
#include "context.h"
#include "media_log.h"

#define FILE_MODE 0777

namespace OHOS {
namespace Media {
class MediaScannerAbilityService : public MediaScannerAbilityStub {
public:
    MediaScannerAbilityService() = default;
    ~MediaScannerAbilityService() = default;

    int32_t ScanDirService(std::string &scanDirPath, const sptr<IRemoteObject> &callback) override;
    int32_t ScanFileService(std::string &scanFilePath, const sptr<IRemoteObject> &callback) override;

private:
    int32_t GetAvailableRequestId();

    MediaScanner *mediaScannerInstance_ = nullptr;
    void StoreCallbackPtrInMap(int32_t reqId, sptr<IRemoteObject>& callback);
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_SCANNER_ABILITY_SERVICE_H