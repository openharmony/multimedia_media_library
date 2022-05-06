/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef MEDIA_SCANNER_ABILITY_H
#define MEDIA_SCANNER_ABILITY_H

#include "imedia_scanner_ability.h"
#include "ability.h"
#include "ability_loader.h"
#include "context.h"
#include "uri.h"
#include "want.h"
#include "media_scanner_ability_service.h"
#include "ability_manager_client.h"
#include "ability_manager_interface.h"
#include "string_ex.h"


namespace OHOS {
namespace Media {
class MediaScannerAbility : public OHOS::AppExecFwk::Ability {
public:
    MediaScannerAbility() = default;
    ~MediaScannerAbility() = default;

protected:
    virtual void OnStart(const OHOS::AAFwk::Want &want) override;
    virtual void OnDisconnect(const OHOS::AAFwk::Want &want) override;
    virtual sptr<IRemoteObject> OnConnect(const OHOS::AAFwk::Want &want) override;
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_SCANNER_ABILITY_H
