/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#define MLOG_TAG "CheckStatusHelper"

#include "check_status_helper.h"

#include <cinttypes>

#include "media_file_utils.h"
#include "media_log.h"

namespace OHOS::Media {
const std::string KEY_LAST_FILE_ID = "last_file_id";
const std::string KEY_LAST_ALBUM_ID = "last_album_id";
const std::string KEY_LAST_CHECK_TIME_IN_MS = "last_check_time_in_ms";

int32_t CheckStatusHelper::GetInt32ValueByKey(const std::string &key, int32_t defaultValue)
{
    auto prefs = GetPreferences();
    CHECK_AND_RETURN_RET_LOG(prefs != nullptr, defaultValue, "GetPreferences failed");
    return prefs->GetInt(key, defaultValue);
}

void CheckStatusHelper::SetInt32ValueByKey(const std::string &key, int32_t value)
{
    auto prefs = GetPreferences();
    CHECK_AND_RETURN_LOG(prefs != nullptr, "GetPreferences failed");
    prefs->PutInt(key, value);
    prefs->FlushSync();
    MEDIA_INFO_LOG("%{public}s: %{public}d", key.c_str(), value);
}

int64_t CheckStatusHelper::GetInt64ValueByKey(const std::string &key, int64_t defaultValue)
{
    auto prefs = GetPreferences();
    CHECK_AND_RETURN_RET_LOG(prefs != nullptr, defaultValue, "GetPreferences failed");
    return prefs->GetLong(key, defaultValue);
}

void CheckStatusHelper::SetInt64ValueByKey(const std::string &key, int64_t value)
{
    auto prefs = GetPreferences();
    CHECK_AND_RETURN_LOG(prefs != nullptr, "GetPreferences failed");
    prefs->PutLong(key, value);
    prefs->FlushSync();
    MEDIA_INFO_LOG("%{public}s: %{public}" PRId64, key.c_str(), value);
}

int64_t CheckStatusHelper::GetLastCheckTimeInMs(int64_t defaultValue)
{
    return GetInt64ValueByKey(KEY_LAST_CHECK_TIME_IN_MS, defaultValue);
}

ConsistencyCheck::ScenarioProgress CheckStatusHelper::GetScenarioProgress()
{
    ConsistencyCheck::ScenarioProgress progress;
    auto prefs = GetPreferences();
    CHECK_AND_RETURN_RET_LOG(prefs != nullptr, progress, "GetPreferences failed");
    progress.lastFileId = prefs->GetInt(KEY_LAST_FILE_ID, 0);
    progress.lastAlbumId = prefs->GetInt(KEY_LAST_ALBUM_ID, 0);
    MEDIA_INFO_LOG("Get %{public}s", progress.ToString().c_str());
    return progress;
}

void CheckStatusHelper::SetValuesByCurrentProgress(const ConsistencyCheck::ScenarioProgress &progress)
{
    auto prefs = GetPreferences();
    CHECK_AND_RETURN_LOG(prefs != nullptr, "GetPreferences failed");
    prefs->PutInt(KEY_LAST_FILE_ID, progress.lastFileId);
    prefs->PutInt(KEY_LAST_ALBUM_ID, progress.lastAlbumId);
    prefs->FlushSync();
    MEDIA_INFO_LOG("Set %{public}s", progress.ToString().c_str());
}

void CheckStatusHelper::SetValuesByFinishedProgress(const ConsistencyCheck::ScenarioProgress &progress)
{
    auto prefs = GetPreferences();
    CHECK_AND_RETURN_LOG(prefs != nullptr, "GetPreferences failed");
    prefs->PutInt(KEY_LAST_FILE_ID, progress.lastFileId);
    prefs->PutInt(KEY_LAST_ALBUM_ID, progress.lastAlbumId);
    prefs->PutLong(KEY_LAST_CHECK_TIME_IN_MS, progress.lastCheckTimeInMs);
    prefs->FlushSync();
    MEDIA_INFO_LOG("Set %{public}s", progress.ToString().c_str());
}

std::shared_ptr<NativePreferences::Preferences> CheckStatusHelper::GetPreferences()
{
    if (prefs_ != nullptr) {
        return prefs_;
    }
    std::string xmlPath = "/data/storage/el2/base/preferences/consistency_check_" +
        std::to_string(static_cast<int32_t>(scene_)) + ".xml";
    int32_t errCode;
    prefs_ = NativePreferences::PreferencesHelper::GetPreferences(xmlPath, errCode);
    CHECK_AND_PRINT_LOG(prefs_ != nullptr, "Get preferences failed, err: %{public}d, scene: %{public}d",
        errCode, static_cast<int32_t>(scene_));
    return prefs_;
}
}  // namespace OHOS::Media