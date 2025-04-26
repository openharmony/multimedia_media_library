/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "medialibraryappstateobserver_fuzzer.h"

#include <cstddef>
#include <sstream>
#include <string>

#include "medialibrary_appstate_observer.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "media_app_uri_permission_column.h"
#include "media_app_uri_sensitive_column.h"
#include "media_library_manager.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "system_ability_definition.h"
#include "ability_info.h"
#include "app_state_data.h"

namespace OHOS {
using namespace std;
using namespace DataShare;
using namespace OHOS::AppExecFwk;
using OHOS::AppExecFwk::AppStateData;
const int32_t EVEN = 2;

static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    return static_cast<int32_t>(*data);
}

static inline int32_t FuzzUInt32(const uint8_t *data, size_t size)
{
    return static_cast<uint32_t>(*data);
}

static inline bool FuzzBool(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return false;
    }
    return (data[0] % EVEN) == 0;
}

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline std::vector<int32_t> FuzzVector(const uint8_t* data, size_t size)
{
    return {FuzzInt32(data, size)};
}

static inline AppExecFwk::ExtensionAbilityType FuzzExtensionAbilityType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(AppExecFwk::ExtensionAbilityType::FORM) &&
        value <= static_cast<int32_t>(AppExecFwk::ExtensionAbilityType::SYSPICKER_SHARE)) {
        return static_cast<AppExecFwk::ExtensionAbilityType>(value);
    }
    return  AppExecFwk::ExtensionAbilityType::SYSPICKER_SHARE;
}

static AppExecFwk::AppStateData FuzzAppStateData(const uint8_t* data, size_t size)
{
    AppExecFwk::AppStateData appStateData;
    appStateData.isFocused = FuzzBool(data, size);
    appStateData.isSplitScreenMode = FuzzBool(data, size);
    appStateData.isFloatingWindowMode = FuzzBool(data, size);
    appStateData.isSpecifyTokenId = FuzzBool(data, size);
    appStateData.isPreloadModule = FuzzBool(data, size);
    appStateData.pid = FuzzInt32(data, size);
    appStateData.uid = FuzzInt32(data, size);
    appStateData.state = FuzzInt32(data, size);
    appStateData.appIndex = FuzzInt32(data, size);
    appStateData.accessTokenId = FuzzUInt32(data, size);
    appStateData.extensionType =  FuzzExtensionAbilityType(data, size);
    appStateData.renderPids = FuzzVector(data, size);
    appStateData.bundleName = FuzzString(data, size);
    appStateData.callerBundleName = FuzzString(data, size);
    return appStateData;
}

static void AppStateObserver(const uint8_t* data, size_t size)
{
    AppExecFwk::AppStateData appStateData = FuzzAppStateData(data, size);
    sptr<Media::MedialibraryAppStateObserver> appStateObserver =
        new (std::nothrow) Media::MedialibraryAppStateObserver();
    appStateObserver->OnAppStopped(appStateData);
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::AppStateObserver(data, size);
    return 0;
}
