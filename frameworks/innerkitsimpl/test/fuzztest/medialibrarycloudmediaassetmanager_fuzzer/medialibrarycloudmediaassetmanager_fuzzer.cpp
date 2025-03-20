/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "medialibrarycloudmediaassetmanager_fuzzer.h"

#include <cstdint>
#include <string>
#include <pixel_map.h>

#define private public
#include "cloud_media_asset_manager.h"
#include "cloud_media_asset_download_operation.h"
#include "cloud_media_asset_callback.h"
#include "cloud_media_asset_observer.h"
#include "cloud_media_asset_types.h"
#undef private
#include "ability_context_impl.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace AbilityRuntime;
using namespace FileManagement::CloudSync;
using Status = CloudMediaAssetDownloadOperation::Status;
static const string DELETE_DISPLAY_NAME = "cloud_media_asset_deleted";
const int32_t EVEN = 2;
static const int32_t POSITION_CLOUD_FLAG = 2;
static const string PHOTOS_TABLE = "Photos";
std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;

static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    return static_cast<int32_t>(*data);
}

static inline int64_t FuzzInt64(const uint8_t *data, size_t size)
{
    return static_cast<int64_t>(*data);
}

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline bool FuzzBool(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return false;
    }
    return (data[0] % EVEN) == 0;
}

static inline CloudMediaDownloadType FuzzCloudMediaDownloadType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(CloudMediaDownloadType::DOWNLOAD_FORCE) &&
        value <= static_cast<int32_t>(CloudMediaDownloadType::DOWNLOAD_GENTLE)) {
        return static_cast<CloudMediaDownloadType>(value);
    }
    return CloudMediaDownloadType::DOWNLOAD_FORCE;
}

static inline CloudMediaTaskRecoverCause FuzzCloudMediaTaskRecoverCause(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(CloudMediaTaskRecoverCause::FOREGROUND_TEMPERATURE_PROPER) &&
        value <= static_cast<int32_t>(CloudMediaTaskRecoverCause::RETRY_FOR_CLOUD_ERROR)) {
        return static_cast<CloudMediaTaskRecoverCause>(value);
    }
    return CloudMediaTaskRecoverCause::RETRY_FOR_CLOUD_ERROR;
}

static inline CloudMediaTaskPauseCause FuzzCloudMediaTaskPauseCause(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(CloudMediaTaskPauseCause::NO_PAUSE) &&
        value <= static_cast<int32_t>(CloudMediaTaskPauseCause::USER_PAUSED)) {
        return static_cast<CloudMediaTaskPauseCause>(value);
    }
    return CloudMediaTaskPauseCause::NO_PAUSE;
}

static inline CloudMediaAssetTaskStatus FuzzCloudMediaAssetTaskStatus(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(CloudMediaAssetTaskStatus::DOWNLOADING) &&
        value <= static_cast<int32_t>(CloudMediaAssetTaskStatus::IDLE)) {
        return static_cast<CloudMediaAssetTaskStatus>(value);
    }
    return CloudMediaAssetTaskStatus::IDLE;
}

static inline Status FuzzStatus(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Status::FORCE_DOWNLOADING) &&
        value <= static_cast<int32_t>(Status::IDLE)) {
        return static_cast<Status>(value);
    }
    return Status::IDLE;
}

static inline DownloadProgressObj::DownloadErrorType FuzzDownloadErrorType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(DownloadProgressObj::DownloadErrorType::NO_ERROR) &&
        value <= static_cast<int32_t>(DownloadProgressObj::DownloadErrorType::FREQUENT_USER_REQUESTS)) {
        return static_cast<DownloadProgressObj::DownloadErrorType>(value);
    }
    return DownloadProgressObj::DownloadErrorType::NO_ERROR;
}

static int32_t InsertAsset(const uint8_t *data, size_t size)
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_FILE_PATH, FuzzString(data, size));
    values.PutLong(MediaColumn::MEDIA_DATE_TAKEN, FuzzInt64(data, size));
    values.PutInt(PhotoColumn::PHOTO_POSITION, POSITION_CLOUD_FLAG);
    values.PutInt(PhotoColumn::PHOTO_SYNC_STATUS, static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE));
    values.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN));
    values.PutInt(PhotoColumn::MEDIA_TYPE, static_cast<int32_t>(MEDIA_TYPE_IMAGE));
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

static int32_t InsertDeleteAsset(const uint8_t *data, size_t size)
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_FILE_PATH, FuzzString(data, size));
    values.PutLong(MediaColumn::MEDIA_DATE_TAKEN, FuzzInt64(data, size));
    values.PutString(MediaColumn::MEDIA_NAME, DELETE_DISPLAY_NAME);
    values.PutInt(PhotoColumn::PHOTO_POSITION, POSITION_CLOUD_FLAG);
    values.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN));
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

static inline Uri FuzzUri(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(CLOUD_MEDIA_ASSET_MANAGER_FUZZER_URI_LISTS.size());
    if (*data < length) {
        string uriStr = CLOUD_MEDIA_ASSET_MANAGER_FUZZER_URI_LISTS[*data];
        Uri uri(uriStr);
        return uri;
    }
    return Uri("Undefined");
}

static inline MediaLibraryCommand FuzzMediaLibraryCmd(const uint8_t *data, size_t size)
{
    return MediaLibraryCommand(FuzzUri(data, size));
}

void SetTables()
{
    vector<string> createTableSqlList = { PhotoColumn::CREATE_PHOTO_TABLE };
    for (auto &createTableSql : createTableSqlList) {
        if (g_rdbStore == nullptr) {
            return;
        }
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

static void Init()
{
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    int32_t sceneCode = 0;
    auto ret = MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(abilityContextImpl,
        abilityContextImpl, sceneCode);
    CHECK_AND_RETURN_LOG(ret == NativeRdb::E_OK, "InitMediaLibraryMgr failed, ret: %{public}d", ret);

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }
    g_rdbStore = rdbStore;
    SetTables();
}

static void CloudMediaAssetManagerFuzzer(const uint8_t *data, size_t size)
{
    MediaLibraryCommand cmd = FuzzMediaLibraryCmd(data, size);
    CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetUpdateOperations(cmd);
    CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetGetTypeOperations(cmd);
}

static void CloudMediaAssetDownloadFuzzer(const uint8_t *data, size_t size)
{
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    int32_t value = FuzzInt32(data, size);
    instance.CheckDownloadTypeOfTask(static_cast<CloudMediaDownloadType>(value));

    instance.StartDownloadCloudAsset(static_cast<CloudMediaDownloadType>(value));
    instance.StartDownloadCloudAsset(FuzzCloudMediaDownloadType(data, size));
    instance.RecoverDownloadCloudAsset(FuzzCloudMediaTaskRecoverCause(data, size));
    instance.PauseDownloadCloudAsset(FuzzCloudMediaTaskPauseCause(data, size));
    instance.CancelDownloadCloudAsset();
    instance.GetCloudMediaAssetTaskStatus();
    instance.SetIsThumbnailUpdate();
    instance.GetTaskStatus();
    instance.GetDownloadType();
    instance.SetBgDownloadPermission(FuzzBool(data, size));
    instance.CheckStorageAndRecoverDownloadTask();
}

static void CloudMediaAssetDownloadOperationFuzzer(const uint8_t *data, size_t size)
{
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    int32_t firstFileId = InsertAsset(data, size);
    int32_t secondFileId = InsertAsset(data, size);
    MEDIA_INFO_LOG("firstFileId: %{public}d, secondFileId: %{public}d", firstFileId, secondFileId);
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ = FuzzCloudMediaAssetTaskStatus(data, size);
    instance.StartDownloadCloudAsset(FuzzCloudMediaDownloadType(data, size));
    instance.RecoverDownloadCloudAsset(FuzzCloudMediaTaskRecoverCause(data, size));
    instance.PauseDownloadCloudAsset(FuzzCloudMediaTaskPauseCause(data, size));
    instance.CancelDownloadCloudAsset();
    instance.GetCloudMediaAssetTaskStatus();
    instance.SetIsThumbnailUpdate();
    instance.GetTaskStatus();
    instance.GetDownloadType();
    instance.SetBgDownloadPermission(FuzzBool(data, size));
    instance.CheckStorageAndRecoverDownloadTask();
    operation->SetTaskStatus(FuzzStatus(data, size));
    operation->QueryDownloadFilesNeeded(FuzzBool(data, size));
    operation->isThumbnailUpdate_ = FuzzBool(data, size);
    operation->InitDownloadTaskInfo();
    CloudMediaAssetDownloadOperation::DownloadFileData downloadFileData = operation->ReadyDataForBatchDownload();
    operation->StartFileCacheFailed(FuzzInt64(data, size), FuzzInt64(data, size));
    operation->StartBatchDownload(FuzzInt64(data, size), FuzzInt64(data, size));
    operation->SubmitBatchDownload(downloadFileData, FuzzBool(data, size));
    operation->InitStartDownloadTaskStatus(FuzzBool(data, size));
    operation->DoRelativedRegister();
    operation->ManualActiveRecoverTask(FuzzInt32(data, size));
    operation->pauseCause_ = FuzzCloudMediaTaskPauseCause(data, size);
    operation->PassiveStatusRecoverTask(FuzzCloudMediaTaskRecoverCause(data, size));
    operation->CheckStorageAndRecoverDownloadTask();
    operation->PauseDownloadTask(FuzzCloudMediaTaskPauseCause(data, size));
    operation->SubmitBatchDownloadAgain();
    operation->GetTaskPauseCause();
    operation->GetTaskInfo();
}

static void CloudMediaAssetDownloadCallbackFuzzer(const uint8_t *data, size_t size)
{
    std::shared_ptr<CloudMediaAssetDownloadOperation> operation = CloudMediaAssetDownloadOperation::GetInstance();
    operation->taskStatus_ = CloudMediaAssetTaskStatus::DOWNLOADING;
    DownloadProgressObj downloadProgressObj;
    downloadProgressObj.downloadId = FuzzInt32(data, size);
    downloadProgressObj.downloadErrorType = FuzzDownloadErrorType(data, size);
    downloadProgressObj.path = FuzzString(data, size);
    operation->HandleSuccessCallback(downloadProgressObj);
    operation->HandleFailedCallback(downloadProgressObj);
    operation->HandleStoppedCallback(downloadProgressObj);
}

static void CloudMediaAssetDeleteFuzzer(const uint8_t *data, size_t size)
{
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    instance.StartDeleteCloudMediaAssets();
    instance.StopDeleteCloudMediaAssets();
    instance.UpdateCloudMeidaAssets();

    int32_t fileId = InsertAsset(data, size);
    vector<string> fileIds = { to_string(fileId) };
    instance.DeleteBatchCloudFile(fileIds);
    fileIds.clear();
    vector<string> paths;
    vector<string> dateTakens;
    fileId = InsertAsset(data, size);
    instance.ReadyDataForDelete(fileIds, paths, dateTakens);
    instance.DeleteAllCloudMediaAssetsAsync();
    instance.DeleteEmptyCloudAlbums();
    instance.ForceRetainDownloadCloudMedia();

    int32_t firstFileId = InsertDeleteAsset(data, size);
    int32_t secondFileId = InsertDeleteAsset(data, size);
    instance.UpdateCloudMeidaAssets();
    instance.DeleteAllCloudMediaAssetsAsync();
    firstFileId = InsertDeleteAsset(data, size);
    secondFileId = InsertDeleteAsset(data, size);
    instance.ForceRetainDownloadCloudMedia();
}
} // namespace Media
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Media::Init();
    OHOS::Media::CloudMediaAssetManagerFuzzer(data, size);
    OHOS::Media::CloudMediaAssetDownloadFuzzer(data, size);
    OHOS::Media::CloudMediaAssetDownloadOperationFuzzer(data, size);
    OHOS::Media::CloudMediaAssetDownloadCallbackFuzzer(data, size);
    OHOS::Media::CloudMediaAssetDeleteFuzzer(data, size);
    return 0;
}
