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
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_kvstore_manager.h"
#include "medialibrary_unistore_manager.h"
#include "rdb_predicates.h"
#include "userfile_manager_types.h"

#define private public
#include "thumbnail_aging_helper.h"
#include "thumbnail_file_utils.h"
#include "thumbnail_generate_helper.h"
#include "thumbnail_generate_worker.h"
#include "thumbnail_generate_worker_manager.h"
#include "thumbnail_image_framework_utils.h"
#include "thumbnail_service.h"
#include "thumbnail_source_loading.h"
#include "thumbnail_uri_utils.h"
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
const string TEST_IMAGE_PATH = "/storage/cloud/files/Photo/1/CreateImageLcdTest_001.jpg";
const int32_t EVEN = 2;
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;
const int32_t PIXELMAP_WIDTH_AND_HEIGHT = 1000;
const int32_t REMAINDER_1 = 1;
const int32_t REMAINDER_2 = 2;
const int32_t REMAINDER_3 = 3;
const int32_t REMAINDER_4 = 4;

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
    if (FuzzBool(data, size)) {
        datas.id = to_string(FuzzInt32(data, size));
        datas.dateTaken = to_string(FuzzInt32(data, size));
    }
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

static string FuzzThumbnailUri(const uint8_t* data, size_t size, bool isNeedPath)
{
    if (!FuzzBool(data, size)) {
        return FuzzString(data, size);
    }

    string thumUri = "file://media/Photo/1?operation=thumbnail";
    Media::Size value = FuzzSize(data, size);
    thumUri += "&width=" + to_string(value.width) + "&height=" + to_string(value.height);
    thumUri += "&date_modified=" + to_string(FuzzInt64(data, size));
    int32_t thumbType = abs(FuzzInt32(data, size)) % 4;
    thumUri += "&type=" + to_string(thumbType);
    thumUri += "&begin_stamp=" + to_string(FuzzInt32(data, size));
    if (isNeedPath) {
        thumUri += "&path=" + FuzzString(data, size);
    }
    thumUri += "&date_taken=" + to_string(FuzzInt64(data, size));

    return thumUri;
}

static std::shared_ptr<Media::PixelMap> CreateTestPixelMap(Media::PixelFormat format, bool useDMA)
{
    Media::InitializationOptions opts;
    opts.size.width = PIXELMAP_WIDTH_AND_HEIGHT;
    opts.size.height = PIXELMAP_WIDTH_AND_HEIGHT;
    opts.srcPixelFormat = format;
    opts.pixelFormat = format;
    opts.useDMA = useDMA;
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(opts);
    return pixelMap;
}

static std::shared_ptr<Media::PixelMap> FuzzNormalPixelMap(const uint8_t* data, size_t size, bool isNeedNullptr = false)
{
    int32_t value = abs(FuzzInt32(data, size)) % 3;
    Media::PixelFormat format = Media::PixelFormat::RGBA_8888;
    bool useDMA = FuzzBool(data, size);
    if (value == REMAINDER_1) {
        format = Media::PixelFormat::RGBA_8888;
    } else if (value == REMAINDER_2) {
        format = Media::PixelFormat::RGBA_1010102;
        useDMA = true;
    } else if (!isNeedNullptr) {
        format = Media::PixelFormat::RGBA_8888;
    } else {
        return nullptr;
    }
    return CreateTestPixelMap(format, useDMA);
}

static std::shared_ptr<Media::PixelMap> FuzzYuvPixelMap(const uint8_t* data, size_t size, bool isNeedNullptr = false)
{
    int32_t value = abs(FuzzInt32(data, size)) % 5;
    Media::PixelFormat format = Media::PixelFormat::NV12;
    bool useDMA = FuzzBool(data, size);
    if (value == REMAINDER_1) {
        format = Media::PixelFormat::NV12;
    } else if (value == REMAINDER_2) {
        format = Media::PixelFormat::NV21;
    } else if (value == REMAINDER_3) {
        format = Media::PixelFormat::YCBCR_P010;
        useDMA = true;
    } else if (value == REMAINDER_4) {
        format = Media::PixelFormat::YCRCB_P010;
        useDMA = true;
    } else if (!isNeedNullptr) {
        format = Media::PixelFormat::NV12;
    } else {
        return nullptr;
    }
    return CreateTestPixelMap(format, useDMA);
}

static std::shared_ptr<Media::Picture> FuzzPicture(const uint8_t* data, size_t size,
    bool isNeedGainMap, bool isYuv, bool isNeedNullptr = false)
{
    std::shared_ptr<Media::PixelMap> pixelMap;
    if (isYuv) {
        pixelMap = FuzzYuvPixelMap(data, size, isNeedNullptr);
    } else {
        pixelMap = FuzzNormalPixelMap(data, size, isNeedNullptr);
    }
    if (pixelMap == nullptr) {
        return nullptr;
    }

    auto sourcePtr = Media::Picture::Create(pixelMap);
    std::shared_ptr<Media::Picture> picture = std::move(sourcePtr);
    if (!isNeedGainMap) {
        return picture;
    }

    std::shared_ptr<Media::PixelMap> gainMap;
    if (isYuv) {
        gainMap = FuzzYuvPixelMap(data, size, isNeedNullptr);
    } else {
        gainMap = FuzzNormalPixelMap(data, size, isNeedNullptr);
    }
    if (gainMap == nullptr) {
        return nullptr;
    }

    Media::Size gainMapSize = {gainMap->GetWidth(), gainMap->GetHeight()};
    auto auxiliaryPicturePtr = Media::AuxiliaryPicture::Create(gainMap,
        Media::AuxiliaryPictureType::GAINMAP, gainMapSize);
    std::shared_ptr<Media::AuxiliaryPicture> auxiliaryPicture = std::move(auxiliaryPicturePtr);
    CHECK_AND_RETURN_RET_LOG(auxiliaryPicture != nullptr, nullptr, "Create auxiliaryPicture failed");
    picture->SetAuxiliaryPicture(auxiliaryPicture);
    return picture;
}

static std::string FuzzThumbnailPath(const uint8_t* data, size_t size)
{
    std::string path = "/storage/cloud/files/" + to_string(FuzzInt32(data, size)) + "/fuzztest";
    Media::ThumbnailData thumbnailData;
    thumbnailData.path = path;
    std::string thumbnailDir = Media::ThumbnailFileUtils::GetThumbnailDir(thumbnailData);
    Media::MediaFileUtils::CreateDirectory(thumbnailDir);

    std::string lcdPath = thumbnailDir + "/LCD.jpg";
    Media::MediaFileUtils::CreateFile(lcdPath);

    std::string thumbPath = thumbnailDir + "/THM.jpg";
    Media::MediaFileUtils::CreateFile(thumbPath);

    std::string astcPath = thumbnailDir + "/THM_ASTC.astc";
    Media::MediaFileUtils::CreateFile(astcPath);

    std::string thumbExDir = thumbnailDir + "/THM_EX";
    Media::MediaFileUtils::CreateDirectory(thumbExDir);
    std::string thumbExFile = thumbExDir + "/THM.jpg";
    Media::MediaFileUtils::CreateFile(thumbExFile);
    thumbExFile = thumbExDir + "/LCD.jpg";
    Media::MediaFileUtils::CreateFile(thumbExFile);

    std::string beginTimeStampDir = thumbnailDir + "/beginTimeStampDir0";
    Media::MediaFileUtils::CreateDirectory(beginTimeStampDir);
    std::string beginTimeStampFile = beginTimeStampDir + "/THM.jpg";
    Media::MediaFileUtils::CreateFile(beginTimeStampFile);
    beginTimeStampFile = beginTimeStampDir + "/LCD.jpg";
    Media::MediaFileUtils::CreateFile(beginTimeStampFile);
    return path;
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
    Media::ThumbnailGenerateHelper::CreateAstcMthAndYear(opts);
    RdbPredicates predicates(PHOTOS_TABLE);
    Media::ThumbnailGenerateHelper::CreateLcdBackground(opts);
    Media::ThumbnailGenerateHelper::CreateAstcBatchOnDemand(opts, predicates, FuzzInt32(data, size));
    Media::ThumbnailGenerateHelper::CheckLcdSizeAndUpdateStatus(opts);
    int32_t outLcdCount;
    Media::ThumbnailGenerateHelper::GetLcdCount(opts, outLcdCount);
    vector<Media::ThumbnailData> outDatas;
    Media::ThumbnailGenerateHelper::GetNoLcdData(opts, outDatas);
    outDatas.clear();
    Media::ThumbnailGenerateHelper::GetNoThumbnailData(opts, outDatas);
    outDatas.clear();
    Media::ThumbnailGenerateHelper::GetNoAstcData(opts, outDatas);
    outDatas.clear();
    Media::ThumbnailGenerateHelper::GetLocalNoLcdData(opts, outDatas);
    outDatas.clear();
    int64_t time = FuzzInt64(data, size);
    int32_t count;
    Media::ThumbnailGenerateHelper::GetNewThumbnailCount(opts, time, count);
    Media::ThumbnailData thumbData = FuzzThumbnailData(data, size);
    string fileName;
    int32_t thumbType = abs(FuzzInt32(data, size)) % 4;
    int32_t timeStamp = FuzzInt32(data, size);
    Media::ThumbnailGenerateHelper::GetAvailableFile(opts, thumbData, FuzzThumbnailType(data, size), fileName);
    Media::ThumbnailGenerateHelper::GetAvailableKeyFrameFile(opts, thumbData, thumbType, fileName);
    Media::ThumbnailGenerateHelper::GetThumbnailPixelMap(thumbData, opts, FuzzThumbnailType(data, size));
    Media::ThumbnailGenerateHelper::UpgradeThumbnailBackground(opts, FuzzBool(data, size));
    Media::ThumbnailGenerateHelper::RestoreAstcDualFrame(opts);
    outDatas.clear();
    Media::ThumbnailGenerateHelper::GetThumbnailDataNeedUpgrade(opts, outDatas, FuzzBool(data, size));
    Media::ThumbnailGenerateHelper::CheckMonthAndYearKvStoreValid(opts);
    Media::ThumbnailGenerateHelper::GenerateHighlightThumbnailBackground(opts);
    Media::ThumbRdbOpt optsWithRdb = FuzzThumbRdbOpt(data, size, false);
    if (optsWithRdb.store != nullptr) {
        outDatas.clear();
        Media::ThumbnailGenerateHelper::GetNoHighlightData(optsWithRdb, outDatas);
        outDatas.clear();
        Media::ThumbnailGenerateHelper::GetKeyFrameThumbnailPixelMap(optsWithRdb, timeStamp, thumbType);
        Media::ThumbnailGenerateHelper::CreateThumbnailFileScanedWithPicture(
            optsWithRdb, FuzzPicture(data, size, true, true, true), FuzzBool(data, size));
    }
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

static void Finish()
{
    Media::MediaLibraryKvStoreManager::GetInstance().CloseAllKvStore();
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
}

static void ThumbnailSourceTest2(const uint8_t* data, size_t size)
{
    Media::Size desiredSize = FuzzSize(data, size);
    Media::ThumbnailData thumbnailData = FuzzThumbnailData(data, size);
    Media::SourceLoader sourceLoader(desiredSize, thumbnailData);
    sourceLoader.CreateVideoFramePixelMap();
    sourceLoader.SetCurrentStateFunction();

    thumbnailData = FuzzThumbnailData(data, size);
    thumbnailData.originalPhotoPicture = FuzzPicture(data, size, true, true, true);
    Media::SourceLoader sourceLoader2(desiredSize, thumbnailData);
    sourceLoader2.RunLoading();
    thumbnailData = FuzzThumbnailData(data, size);
    thumbnailData.originalPhotoPicture = FuzzPicture(data, size, false, false, true);
    Media::SourceLoader sourceLoader3(desiredSize, thumbnailData);
    sourceLoader3.CreateSourceFromOriginalPhotoPicture();

    thumbnailData = FuzzThumbnailData(data, size);
    thumbnailData.originalPhotoPicture = FuzzPicture(data, size, true, false, true);
    Media::SourceLoader sourceLoader4(desiredSize, thumbnailData);
    sourceLoader4.CreateSourceWithWholeOriginalPicture();

    thumbnailData = FuzzThumbnailData(data, size);
    thumbnailData.originalPhotoPicture = FuzzPicture(data, size, false, false, true);
    Media::SourceLoader sourceLoader5(desiredSize, thumbnailData);
    sourceLoader5.CreateSourceWithOriginalPictureMainPixel();

    thumbnailData = FuzzThumbnailData(data, size);
    desiredSize = FuzzSize(data, size);
    thumbnailData.path = TEST_IMAGE_PATH;
    thumbnailData.mediaType = Media::MediaType::MEDIA_TYPE_IMAGE;
    thumbnailData.loaderOpts.loadingStates = {
        { Media::SourceState::BEGIN, Media::SourceState::LOCAL_ORIGIN },
        { Media::SourceState::LOCAL_ORIGIN, Media::SourceState::FINISH },
    };
    Media::SourceLoader sourceLoader6(desiredSize, thumbnailData);
    int32_t ret = sourceLoader6.RunLoading();
    MEDIA_INFO_LOG("sourceLoader6.RunLoading image path: %{public}s. ret: %{public}d", TEST_IMAGE_PATH.c_str(), ret);
}

static void ParseFileUriTest(const uint8_t* data, size_t size)
{
    string outFileId;
    string outNetworkId;
    string outTableName;
    Media::Size outSize;
    string outPath;
    int32_t outType = 0;
    int32_t outBeginStamp = 0;
    string uri = FuzzThumbnailUri(data, size, true);
    Media::ThumbnailUriUtils::ParseFileUri(uri, outFileId, outNetworkId, outTableName);
    Media::ThumbnailUriUtils::ParseThumbnailInfo(uri, outFileId, outSize, outPath, outTableName);
    Media::ThumbnailUriUtils::ParseKeyFrameThumbnailInfo(uri, outFileId, outBeginStamp, outType, outPath);
    Media::ThumbnailUriUtils::GetDateTakenFromUri(uri);
    Media::ThumbnailUriUtils::GetDateModifiedFromUri(uri);
    Media::ThumbnailUriUtils::GetFileUriFromUri(uri);
    Media::Size checkSize = FuzzSize(data, size);
    Media::ThumbnailUriUtils::IsOriginalImg(checkSize, outPath);
    Media::ThumbnailUriUtils::CheckSize(checkSize, outPath);
    Media::ThumbnailUriUtils::GetTableFromUri(uri);
}

static void ThumbnailImageFrameworkUtilsTest(const uint8_t* data, size_t size)
{
    int32_t orientation = 0;
    std::shared_ptr<Media::PixelMap> pixelMap = FuzzNormalPixelMap(data, size, true);
    std::shared_ptr<Media::Picture> picture = FuzzPicture(data, size, true, false, true);
    Media::ThumbnailImageFrameWorkUtils::IsYuvPixelMap(pixelMap);
    Media::ThumbnailImageFrameWorkUtils::IsSupportCopyPixelMap(pixelMap);
    Media::ThumbnailImageFrameWorkUtils::CopyPictureSource(picture);
    Media::ThumbnailImageFrameWorkUtils::CopyPixelMapSource(pixelMap);
    Media::ThumbnailImageFrameWorkUtils::GetPictureOrientation(picture, orientation);

    pixelMap = FuzzYuvPixelMap(data, size, false);
    picture = FuzzPicture(data, size, true, true, false);
    Media::ThumbnailImageFrameWorkUtils::IsYuvPixelMap(pixelMap);
    Media::ThumbnailImageFrameWorkUtils::IsSupportCopyPixelMap(pixelMap);
    Media::ThumbnailImageFrameWorkUtils::CopyPictureSource(picture);
    Media::ThumbnailImageFrameWorkUtils::CopyPixelMapSource(pixelMap);
    Media::ThumbnailImageFrameWorkUtils::GetPictureOrientation(picture, orientation);
}

static void ThumbnailFileUtilsTest(const uint8_t* data, size_t size)
{
    Media::ThumbnailData thumbnailData;
    thumbnailData.path = FuzzThumbnailPath(data, size);
    Media::ThumbnailFileUtils::DeleteThumbnailDir(thumbnailData);
    thumbnailData.path = FuzzThumbnailPath(data, size);
    Media::ThumbnailFileUtils::DeleteAllThumbFiles(thumbnailData);
    Media::ThumbnailFileUtils::DeleteMonthAndYearAstc(thumbnailData);
    Media::ThumbnailFileUtils::CheckRemainSpaceMeetCondition(FuzzInt32(data, size));
    Media::ThumbnailFileUtils::DeleteAstcDataFromKvStore(thumbnailData, FuzzThumbnailType(data, size));
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
    OHOS::ThumhnailTest(data, size);
    OHOS::ThumbnailAgingHelperTest(data, size);
    OHOS::ThumbnailGenerateHelperTest(data, size);
    OHOS::ThumbnailGenerateWorkerTest(data, size);
    OHOS::ThumbnailGenerateWorkerManagerTest(data, size);
    OHOS::ThumbnailSourceTest(data, size);
    OHOS::ThumbnailSourceTest2(data, size);
    OHOS::ParseFileUriTest(data, size);
    OHOS::ThumbnailImageFrameworkUtilsTest(data, size);
    OHOS::ThumbnailFileUtilsTest(data, size);
    OHOS::Finish();
    return 0;
}