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

#include "media_scanner_ability.h"

using namespace OHOS::AppExecFwk;
using namespace std;

namespace OHOS {
namespace Media {
REGISTER_AA(MediaScannerAbility);

void MediaScannerAbility::OnStart(const Want &want)
{
    OHOS::AppExecFwk::Ability::OnStart(want);
}

sptr<IRemoteObject> MediaScannerAbility::OnConnect(const Want &want)
{
    OHOS::AppExecFwk::Ability::OnConnect(want);

    // Creating context of parent class and setting the context at scanner
    auto abilityContext = std::make_unique<MediaScannerAbility>(*this);
    MediaScanner::GetMediaScannerInstance()->SetAbilityContext(move(abilityContext));

    // Creating remote object and returning to client
    auto scannerAbilityService = new(std::nothrow) MediaScannerAbilityService();
    CHECK_AND_RETURN_RET_LOG(scannerAbilityService != nullptr, nullptr, "Remote object creation failed at ability");

    return scannerAbilityService->AsObject();
}

void MediaScannerAbility::OnDisconnect(const Want &want)
{
    OHOS::AppExecFwk::Ability::OnDisconnect(want);
}
} // namespace Media
} // namespace OHOS