/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
 
#include "medialibrary_upgrade_utils.h"
 
#include <unordered_map>
#include "medialibrary_db_const.h"
#include "media_log.h"
 
using namespace std;
 
namespace OHOS {
namespace Media {
static unordered_map<int32_t, string> UPGRADE_VALUE_MAP = {
    { VERSION_FIX_DB_UPGRADE_TO_API20, "VERSION_FIX_DB_UPGRADE_TO_API20" },
    { VERSION_UPDATE_PHOTO_ALBUM_DATEMODIFIED_TIGGER, "VERSION_UPDATE_PHOTO_ALBUM_DATEMODIFIED_TIGGER" },
    { VERSION_ADD_RELATIONSHIP_AND_UPDATE_TRIGGER, "VERSION_ADD_RELATIONSHIP_AND_UPDATE_TRIGGER" },
    { VERSION_ADD_APPLINK_VERSION, "VERSION_ADD_APPLINK_VERSION" },
};
 
bool RdbUpgradeUtils::IsUpgrade(shared_ptr<NativePreferences::Preferences> prefs, int32_t version,
    bool isSync)
{
    if (UPGRADE_VALUE_MAP.find(version) == UPGRADE_VALUE_MAP.end()) {
        return false;
    }
 
    int32_t upgradeStatus = UPGRADE_STATUS::UNKNOWN;
    string versionKey = UPGRADE_VALUE_MAP.at(version);
    if (prefs != nullptr) {
        upgradeStatus = prefs->GetInt(versionKey, UPGRADE_STATUS::UNKNOWN);
    }
    MEDIA_INFO_LOG("IsUpgrade current version:%{public}s, current upgradeStatus: %{public}d",
        versionKey.c_str(), upgradeStatus);
    if (upgradeStatus == UPGRADE_STATUS::UNKNOWN) {
        return false;
    }
 
    return isSync ? (upgradeStatus == UPGRADE_STATUS::SYNC || upgradeStatus == UPGRADE_STATUS::ALL) :
        (upgradeStatus == UPGRADE_STATUS::ASYNC || upgradeStatus == UPGRADE_STATUS::ALL);
}
 
void RdbUpgradeUtils::SetUpgradeStatus(shared_ptr<NativePreferences::Preferences> prefs, int32_t version,
    bool isSync)
{
    if (UPGRADE_VALUE_MAP.find(version) == UPGRADE_VALUE_MAP.end()) {
        MEDIA_INFO_LOG("upgrade map value not exist, version: %{public}d", version);
        return;
    }
 
    int32_t currentStatus = UPGRADE_STATUS::UNKNOWN;
    string versionKey = UPGRADE_VALUE_MAP.at(version);
    if (prefs != nullptr) {
        currentStatus = prefs->GetInt(versionKey, UPGRADE_STATUS::UNKNOWN);
    }
    MEDIA_INFO_LOG("SetUpgradeStatus current version:%{public}s, current upgradeStatus: %{public}d",
        versionKey.c_str(), currentStatus);
 
    int32_t nextStatus = UPGRADE_STATUS::UNKNOWN;
    switch (currentStatus) {
        case UPGRADE_STATUS::UNKNOWN:
            nextStatus = isSync ? UPGRADE_STATUS::SYNC : UPGRADE_STATUS::ASYNC;
            break;
        case UPGRADE_STATUS::SYNC:
            nextStatus = isSync ? UPGRADE_STATUS::SYNC : UPGRADE_STATUS::ALL;
            break;
        case UPGRADE_STATUS::ASYNC:
            nextStatus = isSync ? UPGRADE_STATUS::ALL : UPGRADE_STATUS::ASYNC;
            break;
        case UPGRADE_STATUS::ALL:
            nextStatus = isSync ? UPGRADE_STATUS::ALL : UPGRADE_STATUS::ALL;
        default:
            break;
    }
 
    if (prefs != nullptr) {
        prefs->PutInt(versionKey, nextStatus);
        prefs->FlushSync();
        MEDIA_INFO_LOG("version %{public}s set to: %{public}d", versionKey.c_str(), nextStatus);
    }
}
} // namespace Media
} // namespace OHOS