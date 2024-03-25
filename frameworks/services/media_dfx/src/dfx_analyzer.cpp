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
#define MLOG_TAG "DfxAnalyzer"

#include "dfx_analyzer.h"

#include "media_file_utils.h"
#include "media_log.h"
#include "preferences.h"
#include "preferences_helper.h"

namespace OHOS {
namespace Media {

using namespace std;

DfxAnalyzer::DfxAnalyzer()
{
}

DfxAnalyzer::~DfxAnalyzer()
{
}

void DfxAnalyzer::FlushThumbnail(std::unordered_map<std::string, ThumbnailErrorInfo>  &thumbnailErrorMap)
{
    if (thumbnailErrorMap.empty()) {
        return;
    }
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(THUMBNAIL_ERROR_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return;
    }
    for (auto entry: thumbnailErrorMap) {
        string key = entry.first + SPLIT_CHAR + to_string(entry.second.method) + SPLIT_CHAR +
            to_string(entry.second.errCode);
        string value = to_string(entry.second.time);
        prefs->PutString(key, value);
    }
    prefs->FlushSync();
    MEDIA_INFO_LOG("flush %{public}zu itmes", thumbnailErrorMap.size());
}

void DfxAnalyzer::FlushCommonBehavior(std::unordered_map<string, CommonBehavior> &commonBehaviorMap)
{
    if (commonBehaviorMap.empty()) {
        return;
    }
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(COMMON_BEHAVIOR_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return;
    }
    string behaviors;
    for (auto entry: commonBehaviorMap) {
        string bundleName = entry.first;
        if (bundleName == "") {
            continue;
        }
        int32_t times = entry.second.times;
        int32_t oldValue = prefs->GetInt(bundleName, 0);
        prefs->PutInt(bundleName, times + oldValue);
        behaviors += "{" + bundleName + ": " + to_string(times) + "}";
    }
    prefs->FlushSync();
    if (!behaviors.empty()) {
        MEDIA_INFO_LOG("common behavior: %{public}s", behaviors.c_str());
    }
}

void DfxAnalyzer::FlushDeleteBehavior(std::unordered_map<string, int32_t> &deleteBehaviorMap, int32_t type)
{
    if (deleteBehaviorMap.empty()) {
        return;
    }
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(DELETE_BEHAVIOR_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return;
    }
    for (auto entry: deleteBehaviorMap) {
        string bundleName = entry.first;
        int32_t times = entry.second;
        int32_t oldValue = prefs->GetInt(bundleName, 0);
        prefs->PutInt(bundleName + SPLIT_CHAR + to_string(type), times + oldValue);
    }
    prefs->FlushSync();
}
} // namespace Media
} // namespace OHOS