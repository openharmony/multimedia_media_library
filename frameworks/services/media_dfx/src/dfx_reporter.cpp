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
#include "dfx_database_utils.h"
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

void DfxReporter::ReportThumbnailGeneration(const ThumbnailData::GenerateStats &stats)
{
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_THUMBNAIL_GENERATION",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "URI", stats.uri,
        "SCENE", static_cast<int32_t>(stats.scene),
        "OPEN_THUMB_COST", stats.openThumbCost,
        "OPEN_LCD_COST", stats.openLcdCost,
        "SOURCE_TYPE", static_cast<int32_t>(stats.sourceType),
        "SOURCE_WIDTH", stats.sourceWidth,
        "SOURCE_HEIGHT", stats.sourceHeight,
        "TOTAL_COST", static_cast<int32_t>(stats.totalCost),
        "ERROR_CODE", stats.errorCode);
    if (ret != 0) {
        MEDIA_ERR_LOG("ReportThumbnailGeneration error:%{public}d", ret);
    }
}

void DfxReporter::ReportPhotoInfo(int32_t localImageCount, int32_t localVideoCount, int32_t cloudImageCount,
    int32_t cloudVideoCount)
{
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_PHOTO_INFO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "LOCAL_IMAGE_COUNT", localImageCount,
        "LOCAL_VIDEO_COUNT", localVideoCount,
        "CLOUD_IMAGE_COUNT", cloudImageCount,
        "CLOUD_VIDEO_COUNT", cloudVideoCount);
    if (ret != 0) {
        MEDIA_ERR_LOG("ReportPhotoInfo error:%{public}d", ret);
    }
}

void DfxReporter::ReportAlbumInfo(const std::string &albumName, int32_t albumImageCount, int32_t albumVideoCount,
    bool isLocal)
{
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_ALBUM_INFO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "ALBUM_NAME", albumName,
        "ALBUM_IMAGE_COUNT", albumImageCount,
        "ALBUM_VIDEO_COUNT", albumVideoCount,
        "IS_LOCAL", isLocal);
    if (ret != 0) {
        MEDIA_ERR_LOG("ReportAlbumInfo error:%{public}d", ret);
    }
}

void DfxReporter::ReportDirtyCloudPhoto(const std::string &data, int32_t dirty, int32_t cloudVersion)
{
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_DIRTY_CLOUD_PHOTO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "PATH", data,
        "DIRTY", dirty,
        "CLOUD_VERSION", cloudVersion);
    if (ret != 0) {
        MEDIA_ERR_LOG("ReportDirtyCloudPhoto error:%{public}d", ret);
    }
}

void DfxReporter::ReportCommonVersion(int32_t dbVersion)
{
    MEDIA_INFO_LOG("dbVersion: %{public}d, thumbnailVersion: %{public}d", dbVersion, THUMBNAIL_VERSION);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_COMMON_VERSION",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "DB_VERSION", dbVersion,
        "THUMBNAIL_VERSION", THUMBNAIL_VERSION);
    if (ret != 0) {
        MEDIA_ERR_LOG("ReportCommonVersion error:%{public}d", ret);
    }
}

void DfxReporter::ReportAnalysisVersion(const std::string &analysisName, int32_t version)
{
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_ANALYSIS_VERSION",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "NAME", analysisName,
        "VERSION", version);
    if (ret != 0) {
        MEDIA_ERR_LOG("ReportAnalysisVersion error:%{public}d", ret);
    }
}

void DfxReporter::ReportAdaptationToMovingPhoto()
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(ADAPTATION_TO_MOVING_PHOTO_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return;
    }

    string date = DfxUtils::GetCurrentDate();
    string unadaptedAppPackages = prefs->GetString(MOVING_PHOTO_KEY_UNADAPTED_PACKAGE);
    string adaptedAppPackages = prefs->GetString(MOVING_PHOTO_KEY_ADAPTED_PACKAGE);
    int32_t unadaptedAppNum = prefs->GetInt(MOVING_PHOTO_KEY_UNADAPTED_NUM);
    int32_t adaptedAppNum = prefs->GetInt(MOVING_PHOTO_KEY_ADAPTED_NUM);

    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_MOVING_PHOTO_ADAPT",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "DATE", date,
        "UNADAPTED_APP_NUM", unadaptedAppNum,
        "UNADAPTED_APP_PACKAGE", unadaptedAppPackages,
        "ADAPTED_APP_NUM", adaptedAppNum,
        "ADAPTED_APP_PACKAGE", adaptedAppPackages);
    if (ret != 0) {
        MEDIA_ERR_LOG("Report adaptation to moving photo error:%{public}d", ret);
    }

    prefs->Clear();
    prefs->FlushSync();
}

void DfxReporter::ReportStartResult(int32_t scene, int32_t error, int32_t start)
{
    int32_t cost = static_cast<int32_t>(MediaFileUtils::UTCTimeMilliSeconds() - start);
    MEDIA_ERR_LOG("SCENE:%{public}d, ERROR:%{public}d, TIME:%{public}d", scene, error, cost);
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_START_RESULT",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "SCENE", scene,
        "ERROR", error,
        "TIME", cost);
    if (ret != 0) {
        MEDIA_ERR_LOG("Report startResult error:%{public}d", ret);
    }
}

void DfxReporter::ReportPhotoRecordInfo()
{
    PhotoRecordInfo photoRecordInfo;
    int32_t result = DfxDatabaseUtils::QueryPhotoRecordInfo(photoRecordInfo);
    if (result != 0) {
        MEDIA_ERR_LOG("QueryPhotoRecordInfo error:%{public}d", result);
        return;
    }
    int32_t imageCount = photoRecordInfo.imageCount;
    int32_t videoCount = photoRecordInfo.videoCount;
    int32_t abnormalSizeCount = photoRecordInfo.abnormalSizeCount;
    int32_t abnormalWidthOrHeightCount = photoRecordInfo.abnormalWidthOrHeightCount;
    int32_t abnormalVideoDurationCount = photoRecordInfo.abnormalVideoDurationCount;
    int32_t toBeUpdatedRecordCount = photoRecordInfo.toBeUpdatedRecordCount;
    int64_t dbFileSize = photoRecordInfo.dbFileSize;
    int ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_DATABASE_INFO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "DB_FILE_SIZE", dbFileSize,
        "IMAGE_COUNT", imageCount,
        "VIDEO_COUNT", videoCount,
        "ABNORMAL_SIZE_COUNT", abnormalSizeCount,
        "ABNORMAL_WIDTH_OR_HEIGHT_COUNT", abnormalWidthOrHeightCount,
        "ABNORMAL_VIDEO_DURATION_COUNT", abnormalVideoDurationCount,
        "ABNORMAL_COUNT_TO_UPDATE", toBeUpdatedRecordCount);
    if (ret != 0) {
        MEDIA_ERR_LOG("ReportPhotoRecordInfo error:%{public}d", ret);
    }
}
} // namespace Media
} // namespace OHOS