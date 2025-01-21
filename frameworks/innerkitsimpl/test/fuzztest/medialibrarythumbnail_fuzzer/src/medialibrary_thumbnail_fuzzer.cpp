/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "medialibrary_thumbnail_fuzzer.h"

#include <cstdint>
#include <string>
#include <pixel_map.h>

#include "ability_context_impl.h"
#include "abs_rdb_predicates.h"
#include "cloud_thumbnail_observer.h"
#include "datashare_helper.h"
#include "image_type.h"
#include "ithumbnail_helper.h"
#include "media_column.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unistore_manager.h"
#include "rdb_predicates.h"
#include "thumbnail_uri_utils.h"
#include "userfile_manager_types.h"

#define private public
#include "thumbnail_aging_helper.h"
#include "thumbnail_generate_helper.h"
#include "thumbnail_generate_worker.h"
#include "thumbnail_generate_worker_manager.h"
#include "thumbnail_service.h"
#include "thumbnail_source_loading.h"
#undef private

namespace OHOS {
using namespace std;
using namespace DataShare;
using namespace DistributedKv;
using namespace NativeRdb;
using namespace AAFwk;
using ChangeType = DataShare::DataShareObserver::ChangeType;
using ThumbnailGenerateExecute = void (*)(std::shared_ptr<Media::ThumbnailTaskData> &data);
using ThumbnailWorkerPtr = std::shared_ptr<Media::ThumbnailGenerateWorker>;
const int32_t PRIORITY_DEFAULT = -1;
const int32_t THUMBNAIL_TASK_TYPE_DEFAULT = -1;
const string PHOTOS_TABLE = "Photos";
const int32_t EVEN = 2;
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
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

static inline bool FuzzBool(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return false;
    }
    return (data[0] % EVEN) == 0;
}

static inline Media::ThumbnailType FuzzThumbnailType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::ThumbnailType::LCD) &&
        value <= static_cast<int32_t>(Media::ThumbnailType::THUMB_EX)) {
        return static_cast<Media::ThumbnailType>(value);
    }
    return Media::ThumbnailType::LCD;
}

static inline Media::Size FuzzSize(const uint8_t* data, size_t size)
{
    Media::Size value;
    const int32_t int32Count = 2;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return value;
    }
    int32_t offset = 0;
    value.width = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    value.height = FuzzInt32(data + offset, size);
    return value;
}

static inline Media::PixelFormat FuzzPixelFormat(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::PixelFormat::UNKNOWN) &&
        value <= static_cast<int32_t>(Media::PixelFormat::ASTC_8x8)) {
        return static_cast<Media::PixelFormat>(value);
    }
    return Media::PixelFormat::ARGB_8888;
}

static inline Media::DecodeOptions FuzzDecodeOptions(const uint8_t* data, size_t size)
{
    Media::DecodeOptions value;
    value.desiredPixelFormat = FuzzPixelFormat(data, size);
    return value;
}

static inline Media::ThumbnailTaskType FuzzThumbnailTaskType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::ThumbnailTaskType::FOREGROUND) &&
        value <= static_cast<int32_t>(Media::ThumbnailTaskType::BACKGROUND)) {
        return static_cast<Media::ThumbnailTaskType>(value);
    }
    if (value == THUMBNAIL_TASK_TYPE_DEFAULT) {
        return static_cast<Media::ThumbnailTaskType>(THUMBNAIL_TASK_TYPE_DEFAULT);
    }
    return Media::ThumbnailTaskType::FOREGROUND;
}

static Media::ThumbRdbOpt FuzzThumbRdbOpt(const uint8_t* data, size_t size, bool isNeedNullptr)
{
    std::shared_ptr<Media::MediaLibraryRdbStore> store;
    if (isNeedNullptr) {
        store = FuzzBool(data, size) ?
            Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore() : nullptr;
    } else {
        store = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    }

    Media::ThumbRdbOpt opt = {
        .store = store,
        .networkId = FuzzString(data, size),
        .path = FuzzString(data, size),
        .table = FuzzBool(data, size) ? PHOTOS_TABLE : FuzzString(data, size),
        .row = FuzzString(data, size),
        .dateTaken = FuzzString(data, size),
        .fileUri = FuzzString(data, size)
    };
    return opt;
}

static inline Media::MediaType FuzzMediaType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::MediaType::MEDIA_TYPE_FILE) &&
        value <= static_cast<int32_t>(Media::MediaType::MEDIA_TYPE_DEFAULT)) {
        return static_cast<Media::MediaType>(value);
    }
    return Media::MediaType::MEDIA_TYPE_IMAGE;
}

static Media::ThumbnailData FuzzThumbnailData(const uint8_t* data, size_t size)
{
    Media::ThumbnailData datas;
    datas.path = FuzzString(data, size);
    datas.mediaType = FuzzMediaType(data, size);
    return datas;
}

static Media::ThumbnailTaskPriority FuzzThumbnailTaskPriority(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::ThumbnailTaskPriority::HIGH) &&
        value <= static_cast<int32_t>(Media::ThumbnailTaskPriority::LOW)) {
        return static_cast<Media::ThumbnailTaskPriority>(value);
    }
    if (value == PRIORITY_DEFAULT) {
        return static_cast<Media::ThumbnailTaskPriority>(PRIORITY_DEFAULT);
    }
    return Media::ThumbnailTaskPriority::LOW;
}

static void ThumbnailAgingHelperTest(const uint8_t* data, size_t size)
{
    const int64_t int64Count = 2;
    if (data == nullptr || size <  sizeof(int32_t) + sizeof(int64_t) * int64Count) {
        return;
    }
    Media::ThumbRdbOpt opt = FuzzThumbRdbOpt(data, size, false);
    Media::ThumbnailAgingHelper::AgingLcdBatch(opt);
    int64_t offset = 0;
    int64_t time = FuzzInt64(data + offset, size);
    bool before = FuzzBool(data, size);
    int outLcdCount;
    Media::ThumbnailAgingHelper::GetAgingDataCount(time, before, opt, outLcdCount);

    vector<Media::ThumbnailData> infos;
    offset += sizeof(int32_t);
    Media::ThumbnailAgingHelper::GetAgingLcdData(opt, FuzzInt32(data + offset, size), infos);
    offset += sizeof(int64_t);
    Media::ThumbnailAgingHelper::GetLcdCountByTime(FuzzInt64(data + offset, size), FuzzBool(data, size),
        opt, outLcdCount);
}

static void ThumbnailGenerateHelperTest(const uint8_t* data, size_t size)
{
    Media::ThumbRdbOpt opts = FuzzThumbRdbOpt(data, size, true);
    Media::ThumbnailGenerateHelper::CreateThumbnailFileScaned(opts, FuzzBool(data, size));
    Media::ThumbnailGenerateHelper::CreateThumbnailBackground(opts);
    Media::ThumbnailGenerateHelper::CreateAstcBackground(opts);
    Media::ThumbnailGenerateHelper::CreateAstcCloudDownload(opts, FuzzBool(data, size));
    RdbPredicates predicates(PHOTOS_TABLE);
    Media::ThumbnailGenerateHelper::CreateLcdBackground(opts);
    int32_t outLcdCount;
    Media::ThumbnailGenerateHelper::GetLcdCount(opts, outLcdCount);
    vector<Media::ThumbnailData> outDatas;
    Media::ThumbnailGenerateHelper::GetNoLcdData(opts, outDatas);
    outDatas.clear();
    Media::ThumbnailGenerateHelper::GetNoThumbnailData(opts, outDatas);
    outDatas.clear();
    Media::ThumbnailGenerateHelper::GetNoAstcData(opts, outDatas);
    int64_t time = FuzzInt64(data, size);
    int32_t count;
    Media::ThumbnailGenerateHelper::GetNewThumbnailCount(opts, time, count);
    Media::ThumbnailData thumbData = FuzzThumbnailData(data, size);
    string fileName;
    Media::ThumbnailGenerateHelper::GetAvailableFile(opts, thumbData, FuzzThumbnailType(data, size), fileName);
    Media::ThumbnailGenerateHelper::GetThumbnailPixelMap(opts, FuzzThumbnailType(data, size));
    Media::ThumbnailGenerateHelper::UpgradeThumbnailBackground(opts, FuzzBool(data, size));
    Media::ThumbnailGenerateHelper::RestoreAstcDualFrame(opts);
    outDatas.clear();
    Media::ThumbnailGenerateHelper::GetThumbnailDataNeedUpgrade(opts, outDatas, FuzzBool(data, size));
    Media::ThumbnailGenerateHelper::CheckMonthAndYearKvStoreValid(opts);
}

static void ThumbnailGenerateWorkerTest(const uint8_t* data, size_t size)
{
    Media::ThumbRdbOpt opts = FuzzThumbRdbOpt(data, size, false);
    Media::ThumbnailData thumbnailData = FuzzThumbnailData(data, size);
    std::shared_ptr<Media::ThumbnailTaskData> taskData =
        std::make_shared<Media::ThumbnailTaskData>(opts, thumbnailData, FuzzInt32(data, size));
    std::shared_ptr<Media::ThumbnailGenerateTask> task =
        std::make_shared<Media::ThumbnailGenerateTask>(Media::IThumbnailHelper::CreateLcdAndThumbnail, taskData);

    std::shared_ptr<Media::ThumbnailGenerateWorker> workerPtr = std::make_shared<Media::ThumbnailGenerateWorker>();
    Media::ThumbnailTaskPriority priority = FuzzThumbnailTaskPriority(data, size);
    workerPtr->AddTask(task, priority);
    workerPtr->ReleaseTaskQueue(priority);
}

static void ThumbnailGenerateWorkerManagerTest(const uint8_t* data, size_t size)
{
    Media::ThumbnailTaskType type = FuzzThumbnailTaskType(data, size);
    auto& manager = Media::ThumbnailGenerateWorkerManager::GetInstance();
    manager.InitThumbnailWorker(type);
    manager.ClearAllTask();

    manager.InitThumbnailWorker(type);
    manager.TryCloseThumbnailWorkerTimer();
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

static void ThumhnailTest(const uint8_t* data, size_t size)
{
    const int32_t int32Count = 4;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t offset = 0;
    Media::ThumbnailService::GetInstance()->GetThumbnailFd(FuzzString(data, size),
        FuzzInt32(data + offset, size));
    string thumUri = "file://media/Photo/1?operation=thumbnail&width=-1&height=-1";
    offset += sizeof(int32_t);
    Media::ThumbnailService::GetInstance()->GetThumbnailFd(thumUri, FuzzInt32(data + offset, size));
    Media::ThumbnailService::GetInstance()->LcdAging();
    offset += sizeof(int32_t);
    Media::ThumbnailService::GetInstance()->CreateThumbnailFileScaned(FuzzString(data, size),
        FuzzString(data, size), FuzzInt32(data + offset, size));
    offset += sizeof(int32_t);
    NativeRdb::RdbPredicates rdbPredicate("Photos");
    Media::ThumbnailService::GetInstance()->CancelAstcBatchTask(FuzzInt32(data + offset, size));
    Media::ThumbnailService::GetInstance()->GenerateThumbnailBackground();
    Media::ThumbnailService::GetInstance()->UpgradeThumbnailBackground(false);
    Media::ThumbnailService::GetInstance()->RestoreThumbnailDualFrame();
    Media::ThumbnailService::GetInstance()->CheckCloudThumbnailDownloadFinish();
    Media::ThumbnailService::GetInstance()->InterruptBgworker();
}

static void ThumbnailSourceTest(const uint8_t* data, size_t size)
{
    Media::GetLocalThumbnailPath(FuzzString(data, size), FuzzString(data, size));
    int32_t error;
    int32_t minSize = FuzzInt32(data, size);
    Media::ThumbnailData thumbnailData = FuzzThumbnailData(data, size);
    Media::LocalThumbSource::GetSourcePath(thumbnailData, error);
    Media::LocalThumbSource::IsSizeLargeEnough(thumbnailData, minSize);
    thumbnailData = FuzzThumbnailData(data, size);
    Media::LocalLcdSource::GetSourcePath(thumbnailData, error);
    Media::LocalLcdSource::IsSizeLargeEnough(thumbnailData, minSize);
    thumbnailData = FuzzThumbnailData(data, size);
    Media::LocalOriginSource::GetSourcePath(thumbnailData, error);
    Media::LocalOriginSource::IsSizeLargeEnough(thumbnailData, minSize);

    thumbnailData = FuzzThumbnailData(data, size);
    Media::CloudThumbSource::GetSourcePath(thumbnailData, error);
    Media::CloudThumbSource::IsSizeLargeEnough(thumbnailData, minSize);

    thumbnailData = FuzzThumbnailData(data, size);
    Media::CloudLcdSource::GetSourcePath(thumbnailData, error);
    Media::CloudLcdSource::IsSizeLargeEnough(thumbnailData, minSize);

    thumbnailData = FuzzThumbnailData(data, size);
    Media::CloudOriginSource::GetSourcePath(thumbnailData, error);
    Media::CloudOriginSource::IsSizeLargeEnough(thumbnailData, minSize);
    Media::NeedAutoResize(FuzzSize(data, size));

    Media::DecodeOptions decodeOpts = FuzzDecodeOptions(data, size);
    Media::GenDecodeOpts(FuzzSize(data, size), FuzzSize(data, size), decodeOpts);

    thumbnailData = FuzzThumbnailData(data, size);
    Media::Size sourceSize = FuzzSize(data, size);
    Media::Size desiredSize = FuzzSize(data, size);
    Media::ConvertDecodeSize(thumbnailData, sourceSize, desiredSize);
    uint32_t err = 0;
    Media::LoadImageSource(FuzzString(data, size), err);
    desiredSize = FuzzSize(data, size);
    thumbnailData = FuzzThumbnailData(data, size);
    Media::SourceLoader sourceLoader(desiredSize, thumbnailData);
    sourceLoader.CreateVideoFramePixelMap();
    sourceLoader.SetCurrentStateFunction();
}

static void ParseFileUriTest(const uint8_t* data, size_t size)
{
    string outFileId;
    string outNetworkId;
    string outTableName;
    string uri = "file://media/Photo/2";
    Media::ThumbnailUriUtils::ParseFileUri(uri, outFileId, outNetworkId, outTableName);
    Media::ThumbnailUriUtils::GetDateTakenFromUri(FuzzString(data, size));
    Media::ThumbnailUriUtils::GetFileUriFromUri(FuzzString(data, size));
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Init();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::ThumhnailTest(data, size);
    OHOS::ThumbnailAgingHelperTest(data, size);
    OHOS::ThumbnailGenerateHelperTest(data, size);
    OHOS::ThumbnailGenerateWorkerTest(data, size);
    OHOS::ThumbnailGenerateWorkerManagerTest(data, size);
    OHOS::ThumbnailSourceTest(data, size);
    OHOS::ParseFileUriTest(data, size);
    return 0;
}