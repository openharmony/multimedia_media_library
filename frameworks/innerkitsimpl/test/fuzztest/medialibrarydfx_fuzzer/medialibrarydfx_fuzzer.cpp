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

#include "medialibrarydfx_fuzzer.h"

#include <cstdint>
#include <string>

#include "ability_context_impl.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"

#define private public
#include "dfx_collector.h"
#include "dfx_database_utils.h"
#include "dfx_timer.h"
#include "dfx_transaction.h"
#include "dfx_worker.h"
#undef private

namespace OHOS {
using namespace std;
using namespace AbilityRuntime;
const int32_t EVEN = 2;
static const int32_t E_ERR = -1;
const string TABLE = "PhotoAlbum";
const string PHOTOS_TABLE = "Photos";
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;
static inline uint8_t FuzzUInt8(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint8_t)) {
        return 0;
    }
    return *data;
}

static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
    return static_cast<int32_t>(*data);
}
 
static inline int64_t FuzzInt64(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return 0;
    }
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

static inline Media::DfxType FuzzDfxType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value < static_cast<int32_t>(Media::DfxType::ALBUM_REMOVE_PHOTOS)) {
        return Media::DfxType::ALBUM_REMOVE_PHOTOS;
    } else if (value > static_cast<int32_t>(Media::DfxType::TRASH_PHOTO)) {
        return Media::DfxType::TRASH_PHOTO;
    }
    return Media::DfxType::ALBUM_DELETE_ASSETS;
}

static inline Media::DirtyType FuzzDirtyType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::DirtyType::TYPE_SYNCED) &&
        value <= static_cast<int32_t>(Media::DirtyType::TYPE_COPY)) {
        return static_cast<Media::DirtyType>(value);
    }
    return Media::DirtyType::TYPE_COPY;
}

static inline int32_t FuzzPhotoPosition(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::PhotoPosition::LOCAL) &&
        value <= static_cast<int32_t>(Media::PhotoPosition::LOCAL_AND_CLOUD)) {
        return static_cast<Media::PhotoPosition>(value);
    }
    return Media::PhotoPosition::CLOUD;
}

static inline int32_t FuzzPhotoThumbStatus(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::PhotoThumbStatus::DOWNLOADED) &&
        value <= static_cast<int32_t>(Media::PhotoThumbStatus::NOT_DOWNLOADED)) {
        return static_cast<Media::PhotoThumbStatus>(value);
    }
    return Media::PhotoThumbStatus::NOT_DOWNLOADED;
}

static int32_t InsertAlbumAsset(const uint8_t *data, size_t size)
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutInt(Media::PhotoAlbumColumns::ALBUM_SUBTYPE, FuzzInt32(data, size));
    values.PutInt(Media::PhotoAlbumColumns::ALBUM_COUNT, FuzzInt32(data, size));
    values.PutInt(Media::PhotoAlbumColumns::ALBUM_IMAGE_COUNT, FuzzInt32(data, size));
    values.PutInt(Media::PhotoAlbumColumns::ALBUM_VIDEO_COUNT, FuzzInt32(data, size));
    values.PutString(Media::PhotoAlbumColumns::ALBUM_CLOUD_ID, FuzzString(data, size));
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, TABLE, values);
    return static_cast<int32_t>(fileId);
}

static int32_t InsertPhotoAsset(const uint8_t *data, size_t size)
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutInt(Media::PhotoColumn::PHOTO_POSITION, FuzzPhotoPosition(data, size));
    int32_t dirtyType = static_cast<int32_t>(FuzzDirtyType(data, size));
    values.PutInt(Media::PhotoColumn::PHOTO_DIRTY, dirtyType);
    values.PutInt(Media::PhotoColumn::PHOTO_THUMB_STATUS, FuzzPhotoThumbStatus(data, size));
    int64_t thumbnailReady = FuzzBool(data, size) ? 3 : 2;
    values.PutLong(Media::PhotoColumn::PHOTO_THUMBNAIL_READY, thumbnailReady);
    values.PutString(Media::MediaColumn::MEDIA_FILE_PATH, FuzzString(data, size));
    values.PutString(Media::PhotoColumn::PHOTO_CLOUD_ID, FuzzString(data, size));
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

static void DfxCollectorFuzzer(const uint8_t *data, size_t size)
{
    std::shared_ptr<Media::DfxCollector> dfxCollector = std::make_shared<Media::DfxCollector>();
    std::string bundleName = FuzzString(data, size);
    int32_t type = FuzzDfxType(data, size);
    int32_t value = -1;
    dfxCollector->CollectDeleteBehavior(bundleName, type, value);

    type = Media::DfxType::ALBUM_REMOVE_PHOTOS;
    dfxCollector->CollectDeleteBehavior(bundleName, type, value);

    type = Media::DfxType::TRASH_PHOTO;
    dfxCollector->CollectDeleteBehavior(bundleName, type, value);

    type = Media::DfxType::ALBUM_DELETE_ASSETS;
    dfxCollector->CollectDeleteBehavior(bundleName, type, value);

    std::string appName = FuzzString(data, size);
    bool adapted = FuzzBool(data, size);
    dfxCollector->CollectAdaptationToMovingPhotoInfo(appName, adapted);
}

static void DfxDatabaseUtilsFuzzer(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 3;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t offset = 0;
    int32_t fileId = InsertAlbumAsset(data, size);
    MEDIA_INFO_LOG("fileId: %{public}d.", fileId);
    int32_t albumSubtype = FuzzInt32(data + offset, size);
    Media::DfxDatabaseUtils::QueryAlbumInfoBySubtype(albumSubtype);
    fileId = InsertPhotoAsset(data, size);
    MEDIA_INFO_LOG("fileId: %{public}d.", fileId);
    Media::DfxDatabaseUtils::QueryDirtyCloudPhoto();

    offset += sizeof(int32_t);
    int32_t downloadedThumb = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t generatedThumb = FuzzInt32(data + offset, size);
    Media::DfxDatabaseUtils::QueryDownloadedAndGeneratedThumb(downloadedThumb, generatedThumb);

    bool isLocal = FuzzBool(data, size);
    Media::DfxDatabaseUtils::QueryASTCThumb(isLocal);
    Media::DfxDatabaseUtils::QueryLCDThumb(isLocal);
}

static void DfxTimerFuzzer(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 3;
    if (data == nullptr || size < sizeof(int32_t) * int32Count + sizeof(int64_t)) {
        return;
    }
    int32_t offset = 0;
    int32_t type = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t object = FuzzInt32(data + offset, size);
    offset += sizeof(int64_t);
    int64_t timeOut = FuzzInt64(data + offset, size);
    bool isReport = FuzzBool(data, size);
    std::shared_ptr<Media::DfxTimer> dfxTimer = std::make_shared<Media::DfxTimer>(type, object, timeOut, isReport);
    offset += sizeof(int32_t);
    dfxTimer->SetCallerUid(FuzzInt32(data + offset, size));
    dfxTimer->End();
}

static void DfxTransactionFuzzer(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) + sizeof(uint8_t)) {
        return;
    }
    int offset = 0;
    std::string funcName = FuzzString(data, size);
    std::shared_ptr<Media::DfxTransaction> dfxTransaction = std::make_shared<Media::DfxTransaction>(funcName);
    dfxTransaction->Restart();
    dfxTransaction->ReportIfTimeout();
    uint8_t abnormalType = FuzzUInt8(data + offset, size);
    offset += sizeof(int32_t);
    int32_t errCode = FuzzInt32(data + offset, size);
    dfxTransaction->ReportError(abnormalType, errCode);
}

static void DfxWorkerFuzzer()
{
    auto dfxWorker = Media::DfxWorker::GetInstance();
    Media::DfxExecute execute;
    Media::DfxData *dfxData = nullptr;
    std::shared_ptr<Media::DfxTask> task = std::make_shared<Media::DfxTask>(execute, dfxData);
    dfxWorker->GetTask();
    dfxWorker->WaitForTask();
    dfxWorker->StartLoopTaskDelay();
    dfxWorker->taskList_.push_back(task);
    dfxWorker->WaitForTask();
    dfxWorker->End();
}

void SetTables()
{
    vector<string> createTableSqlList = {
        Media::PhotoColumn::CREATE_PHOTO_TABLE,
        Media::PhotoAlbumColumns::CREATE_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        CHECK_AND_RETURN_LOG(g_rdbStore != nullptr, "g_rdbStore is null");
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
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::DfxCollectorFuzzer(data, size);
    OHOS::DfxDatabaseUtilsFuzzer(data, size);
    OHOS::DfxTimerFuzzer(data, size);
    OHOS::DfxTransactionFuzzer(data, size);
    OHOS::DfxWorkerFuzzer();
    return 0;
}