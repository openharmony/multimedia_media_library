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
#include "cloud_media_asset_types.h"
#undef private
#include "ability_context_impl.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"

namespace OHOS {
using namespace std;
using namespace AbilityRuntime;
static const string DELETE_DISPLAY_NAME = "cloud_media_asset_deleted";
const int32_t EVEN = 2;
static const int32_t E_ERR = -1;
static const string PHOTOS_TABLE = "Photos";
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;

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

static inline Media::CloudMediaDownloadType FuzzCloudMediaDownloadType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::CloudMediaDownloadType::DOWNLOAD_FORCE) &&
        value <= static_cast<int32_t>(Media::CloudMediaDownloadType::DOWNLOAD_GENTLE)) {
        return static_cast<Media::CloudMediaDownloadType>(value);
    }
    return Media::CloudMediaDownloadType::DOWNLOAD_FORCE;
}

static inline Media::CloudMediaTaskRecoverCause FuzzCloudMediaTaskRecoverCause(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::CloudMediaTaskRecoverCause::FOREGROUND_TEMPERATURE_PROPER) &&
        value <= static_cast<int32_t>(Media::CloudMediaTaskRecoverCause::RETRY_FOR_CLOUD_ERROR)) {
        return static_cast<Media::CloudMediaTaskRecoverCause>(value);
    }
    return Media::CloudMediaTaskRecoverCause::RETRY_FOR_CLOUD_ERROR;
}

static inline Media::CloudMediaTaskPauseCause FuzzCloudMediaTaskPauseCause(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::CloudMediaTaskPauseCause::NO_PAUSE) &&
        value <= static_cast<int32_t>(Media::CloudMediaTaskPauseCause::USER_PAUSED)) {
        return static_cast<Media::CloudMediaTaskPauseCause>(value);
    }
    return Media::CloudMediaTaskPauseCause::NO_PAUSE;
}

static int32_t InsertAsset(const uint8_t *data, size_t size)
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(Media::MediaColumn::MEDIA_FILE_PATH, FuzzString(data, size));
    values.PutLong(Media::MediaColumn::MEDIA_DATE_TAKEN, FuzzInt64(data, size));
    values.PutString(Media::MediaColumn::MEDIA_NAME, DELETE_DISPLAY_NAME);
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

static inline Uri FuzzUri(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(Media::CLOUD_MEDIA_ASSET_MANAGER_FUZZER_URI_LISTS.size());
    if (*data < length) {
        string uriStr = Media::CLOUD_MEDIA_ASSET_MANAGER_FUZZER_URI_LISTS[*data];
        Uri uri(uriStr);
        return uri;
    }
    return Uri("Undefined");
}

static inline Media::MediaLibraryCommand FuzzMediaLibraryCmd(const uint8_t *data, size_t size)
{
    return Media::MediaLibraryCommand(FuzzUri(data, size));
}

void SetTables()
{
    vector<string> createTableSqlList = { Media::PhotoColumn::CREATE_PHOTO_TABLE };
    for (auto &createTableSql : createTableSqlList) {
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
    auto ret = Media::MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(abilityContextImpl,
        abilityContextImpl, sceneCode);
    CHECK_AND_RETURN_LOG(ret == NativeRdb::E_OK, "InitMediaLibraryMgr failed, ret: %{public}d", ret);

    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }
    g_rdbStore = rdbStore;
    SetTables();
}

static void CloudMediaAssetManagerFuzzer(const uint8_t *data, size_t size)
{
    Media::MediaLibraryCommand cmd = FuzzMediaLibraryCmd(data, size);
    Media::CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetUpdateOperations(cmd);
    Media::CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetGetTypeOperations(cmd);
}

static void CloudMediaAssetDownloadFuzzer(const uint8_t *data, size_t size)
{
    Media::CloudMediaAssetManager &instance =  Media::CloudMediaAssetManager::GetInstance();
    instance.CheckDownloadTypeOfTask(FuzzCloudMediaDownloadType(data, size));

    instance.StartDownloadCloudAsset(FuzzCloudMediaDownloadType(data, size));
    instance.StartDownloadCloudAsset(FuzzCloudMediaDownloadType(data, size));
    instance.RecoverDownloadCloudAsset(FuzzCloudMediaTaskRecoverCause(data, size));
    instance.PauseDownloadCloudAsset(FuzzCloudMediaTaskPauseCause(data, size));
    instance.CancelDownloadCloudAsset();
    instance.GetCloudMediaAssetTaskStatus();
    instance.SetIsThumbnailUpdate();
    instance.GetTaskStatus();
    instance.GetDownloadType();
    instance.SetBgDownloadPermission(FuzzBool(data, size));
}

static void CloudMediaAssetDeleteFuzzer(const uint8_t *data, size_t size)
{
    Media::CloudMediaAssetManager &instance =  Media::CloudMediaAssetManager::GetInstance();
    int32_t fileId = InsertAsset(data, size);
    vector<string> fileIds = { to_string(fileId) };
    instance.DeleteBatchCloudFile(fileIds);
    fileIds.clear();
    vector<string> paths;
    vector<string> dateTakens;
    fileId = InsertAsset(data, size);
    instance.ReadyDataForDelete(fileIds, paths, dateTakens);
    instance.ForceRetainDownloadCloudMedia();
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Init();
    OHOS::CloudMediaAssetManagerFuzzer(data, size);
    OHOS::CloudMediaAssetDownloadFuzzer(data, size);
    OHOS::CloudMediaAssetDeleteFuzzer(data, size);
    return 0;
}
