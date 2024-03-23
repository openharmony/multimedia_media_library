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
#define MLOG_TAG "DfxReporter"

#include "dfx_reporter.h"

#include <vector>

#include "dfx_const.h"
#include "dfx_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "hisysevent.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "medialibrary_data_manager_utils.h"

using namespace std;
namespace OHOS {
namespace Media {
static constexpr char MEDIA_LIBRARY[] = "MEDIALIBRARY";

DfxReporter::DfxReporter()
{
}

DfxReporter::~DfxReporter()
{
}

void DfxReporter::ReportTimeOutOperation(std::string &bundleName, int32_t type, int32_t object, int32_t time)
{
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_TIMEOUT_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "BUNDLE_NAME", bundleName,
        "OPERATION_TYPE", type,
        "OPERATION_OBJECT", object,
        "TIME", time);
    if (ret != 0) {
        MEDIA_ERR_LOG("ReportTimeoutOperation error:%{public}d", ret);
    }
}

int32_t DfxReporter::ReportHighMemoryImageThumbnail(std::string &path, std::string &suffix, int32_t width,
    int32_t height)
{
    if (suffix != "jpg" && suffix != "jpeg" && suffix != "jpe") {
        MEDIA_WARN_LOG("image %{public}s is %{public}s, width: %{public}d, height: %{public}d", path.c_str(),
            suffix.c_str(), width, height);
        return OTHER_FORMAT_IMAGE;
    } else if (width > IMAGE_MIN && height > IMAGE_MIN) {
        MEDIA_WARN_LOG("image %{public}s is too large, width: %{public}d, height: %{public}d", path.c_str(), width,
            height);
        return BIG_IMAGE;
    }
    return COMMON_IMAGE;
}

int32_t DfxReporter::ReportHighMemoryVideoThumbnail(std::string &path, std::string &suffix, int32_t width,
    int32_t height)
{
    if (width >= VIDEO_8K_MIN || height >= VIDEO_8K_MIN) {
        MEDIA_WARN_LOG("video %{public}s is too large, width: %{public}d, height: %{public}d", path.c_str(), width,
            height);
        return BIG_VIDEO;
    }
    return COMMON_VIDEO;
}

void DfxReporter::ReportThumbnailError()
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(THUMBNAIL_ERROR_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return;
    }
    map<string, NativePreferences::PreferencesValue> errorMap = prefs->GetAll();
    for (auto &erroInfo : errorMap) {
        string key = erroInfo.first;
        string value = erroInfo.second;
        vector<string> thumbnailInfo = DfxUtils::Split(key, SPLIT_CHAR);
        if (thumbnailInfo.empty() || thumbnailInfo.size() < 3) { // 3 means length of key
            continue;
        }
        // 0 means index of path
        string path = thumbnailInfo[0];
        // 1 means index of method
        int32_t method = MediaLibraryDataManagerUtils::IsNumber(thumbnailInfo[1]) ? stoi(thumbnailInfo[1]) : 0;
        // 2 means index of error code
        int32_t errorCode = MediaLibraryDataManagerUtils::IsNumber(thumbnailInfo[2]) ? stoi(thumbnailInfo[2]) : 0;
        int64_t time = MediaLibraryDataManagerUtils::IsNumber(value) ? stol(value) : 0;
        int ret = HiSysEventWrite(
            MEDIA_LIBRARY,
            "MEDIALIB_THUMBNAIL_ERROR",
            HiviewDFX::HiSysEvent::EventType::FAULT,
            "PATH", path,
            "METHOD", method,
            "ERROR_CODE", errorCode,
            "TIME", time);
        if (ret != 0) {
            MEDIA_ERR_LOG("ReportThumbnailError error:%{public}d", ret);
        }
    }
    prefs->Clear();
    prefs->FlushSync();
}

void DfxReporter::ReportCommonBehavior()
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(COMMON_BEHAVIOR_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return;
    }
    map<string, NativePreferences::PreferencesValue> errorMap = prefs->GetAll();
    for (auto &erroInfo : errorMap) {
        string bundleName = erroInfo.first;
        int32_t times = static_cast<int32_t>(erroInfo.second);
        int ret = HiSysEventWrite(
            MEDIA_LIBRARY,
            "MEDIALIB_COMMON_STATISTIC",
            HiviewDFX::HiSysEvent::EventType::STATISTIC,
            "BUNDLE_NAME", bundleName,
            "TIMES", times);
        if (ret != 0) {
            MEDIA_ERR_LOG("ReportCommonBehavior error:%{public}d", ret);
        }
    }
    prefs->Clear();
    prefs->FlushSync();
}

void DfxReporter::ReportDeleteStatistic()
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(DELETE_BEHAVIOR_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return;
    }
    map<string, NativePreferences::PreferencesValue> deleteMap = prefs->GetAll();
    for (auto &info : deleteMap) {
        string key = info.first;
        vector<string> deleteInfo = DfxUtils::Split(key, SPLIT_CHAR);
        if (deleteInfo.empty() || deleteInfo.size() < 2) { // 2 means length of key
            continue;
        }
        // 0 means index of bundleName
        string bundleName = deleteInfo[0];
        // 1 means index of type
        int32_t type = MediaLibraryDataManagerUtils::IsNumber(deleteInfo[1]) ? stoi(deleteInfo[1]) : 0;
        int32_t times = static_cast<int32_t>(info.second);
        int ret = HiSysEventWrite(
            MEDIA_LIBRARY,
            "MEDIALIB_DELETE_STATISTIC",
            HiviewDFX::HiSysEvent::EventType::STATISTIC,
            "BUNDLE_NAME", bundleName,
            "TYPE", type,
            "TIMES", times);
        if (ret != 0) {
            MEDIA_ERR_LOG("ReportDeleteBehavior error:%{public}d", ret);
        }
    }
    prefs->Clear();
    prefs->FlushSync();
}

void DfxReporter::ReportDeleteBehavior(string bundleName, int32_t type, std::string path)
{
    if (bundleName == "" || path == "") {
        return;
    }
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_DELETE_BEHAVIOR",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "BUNDLE_NAME", bundleName,
        "TYPE", type,
        "PATH", path);
    if (ret != 0) {
        MEDIA_ERR_LOG("ReportDeleteBehavior error:%{public}d", ret);
    }
}
} // namespace Media
} // namespace OHOS