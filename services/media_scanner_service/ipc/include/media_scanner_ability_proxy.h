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

#ifndef MEDIA_SCANNER_ABILITY_PROXY_H
#define MEDIA_SCANNER_ABILITY_PROXY_H

#include "imedia_scanner_ability.h"
#include "media_scanner_const.h"

#include "iremote_proxy.h"

namespace OHOS {
namespace Media {
class MediaScannerAbilityProxy : public IRemoteProxy<IMediaScannerAbility> {
public:
    explicit MediaScannerAbilityProxy(const sptr<IRemoteObject> &impl);
    virtual ~MediaScannerAbilityProxy() = default;

    int32_t ScanDirService(std::string &scanDirPath, const sptr<IRemoteObject>& callback) override;
    int32_t ScanFileService(std::string &scanFilePath, const sptr<IRemoteObject>& callback) override;
    bool IsScannerRunning() override;

private:
    static inline BrokerDelegator<MediaScannerAbilityProxy> delegator_;
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_SCANNER_ABILITY_PROXY_H